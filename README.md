# Endor Labs Kubernetes Admission Controller Demo

> **Warning:** This project is intended for demo purposes only and should not be considered for production usage.

## Introduction

Artifact signing ensures the integrity and authenticity of software binaries and configurations, safeguarding against unauthorized modifications. Endor Labs provides a secure, transparent, and accessible solution to signing, verifying, and protecting software artifacts to enhance the security of software supply chains. This project provides a demonstration of how a Kubernetes Admission controller can be used to verify container images via the Endor Labs API to ensure that unsigned containers are not admitted to production environments.

## No Warranty

Please be advised that this software is provided on an "as is" basis, without warranty of any kind, express or implied. The authors and contributors make no representations or warranties of any kind concerning the safety, suitability, lack of viruses, inaccuracies, typographical errors, or other harmful components of this software. There are inherent dangers in the use of any software, and you are solely responsible for determining whether this software is compatible with your equipment and other software installed on your equipment.

By using this software, you acknowledge that you have read this disclaimer, understand it, and agree to be bound by its terms and conditions. You also agree that the authors and contributors of this software are not liable for any damages you may suffer as a result of using, modifying, or distributing this software.

## Limitations

- The webhook server is deployed to a hardcoded namespace called "endorlabs-tutorial"
- The controller only targets a hardcoded Kubernetes namespace called "production"
- The controller only validates images which have been signed within a GitHub pipeline using OIDC authentication
- Deployment images must include the hash (tags are not supported), therefore container images should be in the format `IMAGE_NAME@sha256:SHA`

## Requirements

- Administrative access to a Kubernetes cluster to deploy resources including namespaces, pods and secrets (such as minikube)
- An installation of `kubectl`, configured for your cluster
- API key from Endor Labs with the "Code Scanner" permissions
- A Docker registry to store the webhook server container image

## Building

1. Build the container and to push to your preferred container registry:
    1. For a single architecture build run: `docker build -t your-repo/your-image:0.1 .`
    1. For multi-architecture build run: `docker buildx build --platform linux/arm64,linux/amd64 -t your-repo/your-image:0.1 .`
    1. Push to your preferred container registry, e.g. for Docker Hub: `docker push your-repo/your-image:0.1`

## Deployment

1. Make a copy of [webhook_server.template.yml](./manifests/webhook_server.template.yml) named `webhook_server.yml`, then:
    1. Modify the `image:` to match your repo/image/version on [line 20](./manifests/webhook_server.yml#L20)
    1. Modify the Endor `NAMESPACE` value on [line 42](./manifests/webhook_server.yml#L42)
    1. If you're not signing in a GitHub action, modify the  `CERTIFICATE_OIDC_ISSUER` value on [line 44](./manifests/webhook_server.yml#L44)
1. Make a copy of [secrets.template.yml](./manifests/secrets.template.yml) named `secrets.yml` then:
    1. Add your **base64 encoded** Endor API Key on [line 8](./manifests/secrets.yml#L8) 
    1. Add your **base64 encoded** Endor API Secret on [line 9](./manifests/secrets.yml#L9)
1. Run the script `./deploy.sh` which performs the following functions:
    1. Generates TLS certificates to securely communicate with the Kubernetes API server
    1. Creates Kubernetes secrets using your Endor API credentials
    1. Creates the webhook server in a namespace called "endorlabs-tutorial"
    1. Deploys the admission controller webhook to verify if images are signed in a namespace called "production"

## Usage

Once deployed and configured, the Admission Controller automatically validates deployments. It ensures that:

- Each container image in the deployment specifications includes a digest (IMAGE_NAME@sha256:SH)
- Verifies the image was signed using the Endor Labs API

If a deployment does not meet these criteria, it is rejected with a message indicating the reason. 

## Testing 

Attempt to deploy a signed and non-signed image to the "prodution" namespace in your cluster. Verify if the admission controller is working as expected, for a successful verification you should see:

> deployment.apps/\<your image name> created.

For a failure you should see:

> Error from server: error when creating "examples/nginx-unsigned-image.yml": admission webhook "deployment-validation.endorlabs-tutorial.svc" denied the request: Container image signature verification failed for the image \<your image>, with reason: verification failed with result: unable to find signature entry for given artifact

## Return codes

The list of return codes is shown here:

| Code   | Description |
| ------ | ----------- |
| ARTIFACT_OPERATION_RESULT_UNSPECIFIED | "unspecified error" |
| ARTIFACT_OPERATION_RESULT_SUCCESS | "successful operation" |
| ARTIFACT_OPERATION_RESULT_NO_ARTIFACT| "no such artifact" |
| ARTIFACT_OPERATION_RESULT_NO_SIGNATURE | "unable to find signature entry f|or given artifact" |
| ARTIFACT_OPERATION_RESULT_TIME_MISMATCH | "timestamp does not match the certificate's validity" |
| ARTIFACT_OPERATION_RESULT_INVALID_SIGNATURE| "unable to verify signature" |
| ARTIFACT_OPERATION_RESULT_UNKNOWN_CA | "unknown certificate authority (CA)" |
| ARTIFACT_OPERATION_RESULT_REVOKED_SIGNATURE | "the signature for this artifact and source repository reference has been revoked" |
| ARTIFACT_OPERATION_RESULT_CLAIMS_MISMATCH | "provided provenance information does not match with signature entry" |
| ARTIFACT_OPERATION_RESULT_BAD_CERTIFICATE | "bad certificate" |
| ARTIFACT_OPERATION_RESULT_INVALID_KEY_TYPE | "unable to extract public key from certificate" |
| ARTIFACT_OPERATION_RESULT_CORRUPTED_SIGNATURE | "unable to decode signature" |
| ARTIFACT_OPERATION_RESULT_KEY_GEN_FAILURE | "unable to generate private key" |
| ARTIFACT_OPERATION_RESULT_CSR_GEN_FAILURE | "unable to create certificate signing request" |
| ARTIFACT_OPERATION_RESULT_SIGN_FAILURE | "unable to sign artifact" |

## Future Improvements

This Admission Controller is designed as a demonstrative example and *is not intended for production use*. 

Key limitations include:

- The current implementation does not cache or store verification results, potentially leading to redundant verification requests for the same image
- Error handling and logging are basic and may not cover all edge cases or provide enough information for debugging in complex scenarios

## Logs

The Admission Controller logs its operations, including the details of the validation process and any errors encountered during signature verification. Check the webhook server logs for insights into its operation and troubleshooting information:

```
kubectl get pods -n endorlabs-tutorial
kubectl logs <pod name> -n endorlabs-tutorial
```

## Security Considerations

- Ensure that TLS certificates are securely stored and managed
- For production environments, it's advisable to use certificates issued by a trusted CA

### Based on
[Build Your Own Admission Controllers in Kubernetes Using Go](https://bshayr29.medium.com/build-your-own-admission-controllers-in-kubernetes-using-go-bef8ba38d595)