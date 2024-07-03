#!/bin/bash

# Check if key.pem exists
if [ ! -f "key.pem" ]; then
    echo "Error: key.pem not found. Please ensure your private key file exists."
    exit 1
fi

# Configuration for the certificate
COUNTRY="US"
STATE="California"
LOCALITY="San Francisco"
ORGANIZATION="My Organization"
ORGANIZATIONAL_UNIT="IT Department"
COMMON_NAME="example.com"
EMAIL="admin@example.com"

# Create CSR
openssl req -new -key key.pem -out cert.csr -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=$COMMON_NAME/emailAddress=$EMAIL"

# Create self-signed certificate
openssl x509 -req -days 365 -in cert.csr -signkey key.pem -out cert.pem

# Clean up CSR
rm cert.csr

# Verify the certificate
echo "Verifying the certificate:"
openssl x509 -in cert.pem -text -noout

echo "Self-signed certificate created: cert.pem"

# Set the output filename for P12
P12_FILE="certificate.p12"

# Set a friendly name for the certificate
FRIENDLY_NAME="MyCertificate"

# Prompt for a password for the P12 file
echo "Please enter a password to protect the P12 file:"
read -s P12_PASSWORD
echo

# Create the P12 file
openssl pkcs12 -export \
    -inkey key.pem \
    -in cert.pem \
    -out "$P12_FILE" \
    -name "$FRIENDLY_NAME" \
    -passout pass:"$P12_PASSWORD"

# Check if the P12 file was created successfully
if [ $? -eq 0 ]; then
    echo "P12 file created successfully: $P12_FILE"
    
    # Verify the P12 file
    echo "Verifying the P12 file:"
    openssl pkcs12 -info -in "$P12_FILE" -noout -passin pass:"$P12_PASSWORD"
    
    # Set the output filename for JKS
    JKS_FILE="keystore.jks"

    # Convert P12 to JKS
    echo "Converting P12 to JKS..."
    keytool -importkeystore \
        -srckeystore "$P12_FILE" \
        -srcstoretype PKCS12 \
        -srcstorepass "$P12_PASSWORD" \
        -destkeystore "$JKS_FILE" \
        -deststoretype JKS \
        -deststorepass "$P12_PASSWORD" \
        -alias "$FRIENDLY_NAME" \
        -noprompt

    # Check if the JKS file was created successfully
    if [ $? -eq 0 ]; then
        echo "JKS file created successfully: $JKS_FILE"
        
        # Verify the JKS file
        echo "Verifying the JKS file:"
        keytool -list -v -keystore "$JKS_FILE" -storepass "$P12_PASSWORD"
    else
        echo "Failed to create JKS file."
    fi
else
    echo "Failed to create P12 file."
fi
