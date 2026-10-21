
pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 40, unit: 'MINUTES')
    }

    environment {
        IMAGE_NAME = "secureops-demo:${BUILD_NUMBER}"
        TRIVY_CACHE = "/var/jenkins_home/trivy-cache"
    }

    stages {
        stage('Build Docker Image') {
            steps {
                sh '''
                    set -eu
                    docker version
                    docker build -t "$IMAGE_NAME" .
                    docker image inspect "$IMAGE_NAME"
                '''
            }
        }

        stage('Export Image') {
            steps {
                sh '''
                    set -eu
                    mkdir -p "$TRIVY_CACHE"
                    docker save "$IMAGE_NAME" \
                      -o "$WORKSPACE/secureops-demo.tar"
                    test -s "$WORKSPACE/secureops-demo.tar"
                    ls -lh "$WORKSPACE/secureops-demo.tar"
                '''
            }
        }

        stage('Trivy Security Scan') {
            steps {
                sh '''
                    set -eu

                    docker run --rm \
                      -v "$WORKSPACE:/scan" \
                      -v "$TRIVY_CACHE:/root/.cache/" \
                      aquasec/trivy:latest image \
                      --timeout 30m \
                      --input /scan/secureops-demo.tar \
                      --format json \
                      --output /scan/trivy-report.json

                    test -s "$WORKSPACE/trivy-report.json"
                    echo "Trivy report generated."
                    ls -lh "$WORKSPACE/trivy-report.json"
                '''
            }
        }

        stage('Archive Security Report') {
            steps {
                archiveArtifacts(
                    artifacts: 'trivy-report.json',
                    fingerprint: true
                )
            }
        }
    }

    post {
        success {
            echo 'Docker build and Trivy scan succeeded.'
        }
        failure {
            echo 'Pipeline failed. Check the failed stage above.'
        }
    }
}
