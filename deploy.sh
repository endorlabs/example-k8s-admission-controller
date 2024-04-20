#!/bin/bash

echo "Creating certificates"
mkdir -p certs
if [ ! -f certs/tls.key ]; then
    openssl genrsa -out certs/tls.key 2048
else
    echo "TLS key already exists."
fi

if [ ! -f certs/tls.crt ]; then
    openssl req -new -key certs/tls.key -out certs/tls.csr -subj "/CN=webhook-server.endorlabs-tutorial.svc"
    openssl x509 -req -extfile <(printf "subjectAltName=DNS:webhook-server.endorlabs-tutorial.svc") -in certs/tls.csr -signkey certs/tls.key -out certs/tls.crt
else
    echo "TLS certificate already exists."
fi

echo "Creating namespace endorlabs-tutorial"
kubectl get namespace endorlabs-tutorial || kubectl create namespace endorlabs-tutorial
kubectl apply -f manifests/secrets.yml
kubectl apply -f manifests/webhook_server.yml

echo "Creating namespace production"
kubectl get namespace production || kubectl create namespace production

echo "Creating Webhook Server TLS Secret"
kubectl create secret tls webhook-server-tls \
    --cert "certs/tls.crt" \
    --key "certs/tls.key" -n endorlabs-tutorial --dry-run=client -o yaml | kubectl apply -f -

echo "Creating K8s Webhooks"
ENCODED_CA=$(cat certs/tls.crt | base64 | tr -d '\n')
sed -e 's@${ENCODED_CA}@'"$ENCODED_CA"'@g' <"manifests/webhooks.yml" | kubectl apply -f -