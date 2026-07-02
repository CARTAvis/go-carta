#!/bin/bash

if [ ! -d "services" ]; then
    echo -e "Error: Could not find the 'services' folder. Please run the script from the project root directory."
    exit 1
fi

mkdir -p build

# list of services
SERVICES=("carta-ctl" "carta-worker" "carta-spawn" "api")

# Loop through each service and build it
for SERVICE_NAME in "${SERVICES[@]}"; do
    echo "Building ${SERVICE_NAME}..."
    
    if [ "$SERVICE_NAME" = "carta-ctl" ]; then
        # Try building with PAM support first
        if go build -tags=pam -o "./build/${SERVICE_NAME}" "./services/${SERVICE_NAME}/" 2>&1; then
            :
        else
            echo "PAM build failed, building without PAM support."
            if ! go build -o "./build/${SERVICE_NAME}" "./services/${SERVICE_NAME}/"; then
                echo -e "Error: Failed to build ${SERVICE_NAME}."
                exit 1
            fi
        fi
    else
        if ! go build -o "./build/${SERVICE_NAME}" "./services/${SERVICE_NAME}/"; then
            echo -e "Error: Failed to build ${SERVICE_NAME}."
            exit 1
        fi
    fi
    
    echo "${SERVICE_NAME} built successfully."
    echo
done

echo "All services built successfully!"
