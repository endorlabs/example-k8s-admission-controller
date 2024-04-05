package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	admission "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	v1 "k8s.io/kubernetes/pkg/apis/apps/v1"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecFactory  = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecFactory.UniversalDeserializer()
	httpClient    = &http.Client{}

	baseUrl               = os.Getenv("BASEURL")
	endorNamespace        = os.Getenv("NAMESPACE")
	certificateOidcIssuer = os.Getenv("CERTIFICATE_OIDC_ISSUER")
	apiKey                = os.Getenv("API_KEY")
	apiSecret             = os.Getenv("API_SECRET")
)

// add kind AdmissionReview in scheme
func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admission.AddToScheme(runtimeScheme)
	_ = v1.AddToScheme(runtimeScheme)
}

type ApiResponse struct {
	Response struct {
		Result string `json:"result"`
	} `json:"response"`
}

type admitv1Func func(admission.AdmissionReview) *admission.AdmissionResponse

type admitHandler struct {
	v1 admitv1Func
}

func AdmitHandler(f admitv1Func) admitHandler {
	return admitHandler{v1: f}
}

// serve handles the http portion of a request prior to handing to an admit
// function
func serve(w http.ResponseWriter, r *http.Request, admit admitHandler) {
	var body []byte
	if r.Body != nil {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			log.Error().Err(err).Msg("Error reading request body")
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		body = data
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		log.Error().Msgf("Content-Type=%s, expected application/json", contentType)
		http.Error(w, "Invalid Content-Type, expected application/json", http.StatusBadRequest)
		return
	}

	log.Info().Msgf("Handling request: %s", body)
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		log.Error().Err(err).Msg("Request could not be decoded")
		http.Error(w, fmt.Sprintf("Could not decode request: %v", err), http.StatusBadRequest)
		return
	}

	requestedAdmissionReview, ok := obj.(*admission.AdmissionReview)
	if !ok {
		log.Error().Msgf("Expected AdmissionReview but got: %T", obj)
		http.Error(w, "Incorrect request type", http.StatusBadRequest)
		return
	}

	responseAdmissionReview := &admission.AdmissionReview{}
	responseAdmissionReview.SetGroupVersionKind(*gvk)
	responseAdmissionReview.Response = admit.v1(*requestedAdmissionReview)
	responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID

	respBytes, err := json.Marshal(responseAdmissionReview)
	if err != nil {
		log.Error().Err(err).Msg("Error marshalling response")
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}

func serveValidate(w http.ResponseWriter, r *http.Request) {
	serve(w, r, AdmitHandler(validate))
}

// Verify all of the containers are signed using Endor API
func validate(ar admission.AdmissionReview) *admission.AdmissionResponse {
	log.Info().Msgf("Validating deployments for image digests")
	deploymentResource := metav1.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	if ar.Request.Resource != deploymentResource {
		log.Error().Msgf("expect resource to be %s", deploymentResource)
		return nil
	}

	raw := ar.Request.Object.Raw
	deployment := appsv1.Deployment{}
	if _, _, err := deserializer.Decode(raw, nil, &deployment); err != nil {
		log.Err(err).Msg("could not deserialize deployment")
		return &admission.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	for _, container := range deployment.Spec.Template.Spec.Containers {
		if !strings.Contains(container.Image, "@sha256:") {
			return &admission.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "Container image must include a digest: " + container.Image,
				},
			}
		}

		// Verify the image signature using the digest
		imageVerified, err := verifyImageSignature(container.Image)
		if !imageVerified {
			return &admission.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: fmt.Sprintf("Container image signature verification failed for the image %s, with reason: %s", container.Image, err),
				},
			}
		}
	}

	// All images have digests and are verified
	return &admission.AdmissionResponse{Allowed: true}
}

func verifyImageSignature(imageName string) (bool, error) {
	//Fetch a bearer token from the Endor API
	bearerToken, err := fetchBearerToken()
	if err != nil {
		return false, fmt.Errorf("error fetching bearer token: %w", err)
	}

	//Construct the URL for the API call
	url := fmt.Sprintf("%s/v1/namespaces/%s/artifact-operations", baseUrl, endorNamespace)

	requestBody := map[string]interface{}{
		"meta": map[string]string{
			"name": imageName,
		},
		"tenant_meta": map[string]string{
			"namespace": endorNamespace,
		},
		"spec": map[string]interface{}{
			"command":       "ARTIFACT_OPERATION_COMMAND_VERIFY",
			"artifact_name": imageName,
			"artifact_type": "ARTIFACT_TYPE_CONTAINER",
			"extensions": map[string]string{
				"certificate_oidc_issuer": certificateOidcIssuer,
			},
		},
	}

	payloadBytes, err := json.Marshal(requestBody)
	if err != nil {
		return false, fmt.Errorf("error marshalling request body: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return false, fmt.Errorf("error creating request: %w", err)
	}

	// Set the Content-Type and Authorization headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("API request failed with status code %d: %s", resp.StatusCode, string(body))
	}

	// Unmarshal the response body into the ApiResponse struct
	var apiResponse ApiResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return false, fmt.Errorf("error unmarshalling response body: %w", err)
	}

	// Check if the response was successful
	if apiResponse.Response.Result == "VERIFICATION_RESULT_SUCCESS" {
		log.Info().Msg("Verification result was successful")
		return true, nil
	} else {
		return false, fmt.Errorf("verification failed with result: %s", apiResponse.Response.Result)
	}
}

func fetchBearerToken() (string, error) {
	getTokenEndpoint := baseUrl + "/v1/auth/api-key"

	// Construct the request payload
	payload := map[string]string{
		"key":    apiKey,
		"secret": apiSecret,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("error marshalling payload: %w", err)
	}

	// Create a new request using http
	req, err := http.NewRequest("POST", getTokenEndpoint, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status code %d: %s", resp.StatusCode, string(body))
	}

	// Assuming the API returns the token in a JSON field named "token"
	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("error unmarshalling response body: %w", err)
	}

	token, exists := result["token"]
	if !exists {
		return "", fmt.Errorf("token not found in response")
	}

	return token, nil
}

func main() {
	var tlsKey, tlsCert string
	flag.StringVar(&tlsKey, "tlsKey", "/etc/certs/tls.key", "Path to the TLS key")
	flag.StringVar(&tlsCert, "tlsCert", "/etc/certs/tls.crt", "Path to the TLS certificate")
	flag.Parse()
	http.HandleFunc("/validate", serveValidate)
	log.Info().Msg("Server started ...")
	log.Fatal().Err(http.ListenAndServeTLS(":8443", tlsCert, tlsKey, nil)).Msg("webhook server exited")
}
