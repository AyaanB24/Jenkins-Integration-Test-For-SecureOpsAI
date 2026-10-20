pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    environment {
        IMAGE_NAME = 'secureops-demo'
        REPORT_FILE = 'trivy-report.json'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t ${IMAGE_NAME}:${BUILD_NUMBER} .'
            }
        }

        stage('Trivy Security Scan') {
            steps {
                sh '''
                    trivy image \
                      --format json \
                      --output "$REPORT_FILE" \
                      --exit-code 0 \
                      "$IMAGE_NAME:$BUILD_NUMBER"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-report.json',
                                     allowEmptyArchive: false
                }
            }
        }

        stage('Upload Report to SecureOps') {
            steps {
                sh '''
                    test -s "$REPORT_FILE"

                    if [ -z "$SECUREOPS_REPORT_URL" ]; then
                        echo "SecureOps report URL is not configured"
                        exit 1
                    fi

                    curl --fail --silent --show-error \
                      --connect-timeout 10 \
                      --max-time 60 \
                      -X POST \
                      -F "file=@$REPORT_FILE;type=application/json" \
                      "$SECUREOPS_REPORT_URL"
                '''
            }
        }

        // Add report-processing and decision-check stages
        // after confirming the actual SecureOps API contract.
    }

    post {
        success {
            echo 'Build, Trivy scan and configured report upload completed.'
        }
        failure {
            echo 'Pipeline failed. Check the Jenkins console output.'
        }
    }
}