
import groovy.json.JsonOutput

pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        skipDefaultCheckout(true)
        timeout(time: 60, unit: 'MINUTES')
    }

    environment {
        // Jenkins Credentials: Secret text, ID = secureops-api-key
        SECUREOPS_API_KEY = credentials('secureops-api-key')

        // SecureOps backend running on Windows host
        SECUREOPS_URL = 'http://host.docker.internal:8081'

        PROJECT_NAME = 'Jenkins-Integration-Test-For-SecureOpsAI'
        REPOSITORY_URL = 'https://github.com/AyaanB24/Jenkins-Integration-Test-For-SecureOpsAI'

        IMAGE_NAME = 'secureops-demo'
        TRIVY_CACHE = '/var/jenkins_home/trivy-cache'
        SCAN_ENVIRONMENT = 'DEVELOPMENT'
    }

    stages {

        stage('1. Checkout Source') {
            steps {
                checkout scm

                sh '''
                    set -eu
                    echo "Repository checked out."
                    echo "Job: ${JOB_NAME}"
                    echo "Build: ${BUILD_NUMBER}"
                    test -f Dockerfile
                '''
            }
        }

        stage('2. Build Docker Image') {
            steps {
                sh '''
                    set -eu
                    docker version
                    docker build -t "${IMAGE_NAME}:${BUILD_NUMBER}" .
                    echo "Docker image built successfully."
                '''
            }
        }

        stage('3. Export Image and Run Trivy') {
            steps {
                sh '''
                    set -eu

                    mkdir -p "${TRIVY_CACHE}"

                    docker save \
                        "${IMAGE_NAME}:${BUILD_NUMBER}" \
                        -o secureops-demo.tar

                    docker run --rm \
                        -v "${WORKSPACE}:/scan" \
                        -v "${TRIVY_CACHE}:/root/.cache/trivy" \
                        aquasec/trivy:latest \
                        image \
                        --timeout 30m \
                        --input /scan/secureops-demo.tar \
                        --format json \
                        --output /scan/trivy-report.json

                    test -s trivy-report.json
                    echo "Trivy report generated."
                '''

                archiveArtifacts(
                    artifacts: 'trivy-report.json',
                    fingerprint: true
                )
            }
        }

        stage('4. Register Build with SecureOps') {
            steps {
                script {
                    // Find the registered project using API-key authentication.
                    def projectJson = sh(
                        returnStdout: true,
                        script: """
                            set +x
                            curl --fail --silent --show-error \
                              -H "X-API-Key: \$SECUREOPS_API_KEY" \
                              --get \
                              --data-urlencode 'name=${env.PROJECT_NAME}' \
                              '${env.SECUREOPS_URL}/api/projects'
                        """
                    ).trim()

                    def project = readJSON(
                        text: projectJson,
                        returnPojo: true
                    )

                    if (!project.id) {
                        error('SecureOps project was not returned or has no ID.')
                    }

                    if (project.name != env.PROJECT_NAME) {
                        error("Unexpected project returned by SecureOps: ${project.name}")
                    }

                    if (project.repositoryUrl &&
                        !project.repositoryUrl.replaceAll('/+$', '')
                            .replaceAll(/\.git$/, '')
                            .equalsIgnoreCase(
                                env.REPOSITORY_URL.replaceAll('/+$', '')
                                    .replaceAll(/\.git$/, '')
                            )) {
                        error('The registered project repository URL does not match this Jenkins repository.')
                    }

                    env.PROJECT_ID = project.id.toString()

                    echo "SecureOps project found: ${project.name}"
                    echo "Project ID: ${env.PROJECT_ID}"

                    // Check for an existing record for this exact build.
                    def pipelinesJson = sh(
                        returnStdout: true,
                        script: """
                            set +x
                            curl --fail --silent --show-error \
                              -H "X-API-Key: \$SECUREOPS_API_KEY" \
                              '${env.SECUREOPS_URL}/api/projects/${env.PROJECT_ID}/pipelines'
                        """
                    ).trim()

                    def pipelines = readJSON(
                        text: pipelinesJson,
                        returnPojo: true
                    )

                    def existingPipeline = pipelines.find { p ->
                        p.jobName == env.JOB_NAME &&
                        p.buildNumber?.toString() == env.BUILD_NUMBER
                    }

                    if (existingPipeline) {
                        env.PIPELINE_ID = existingPipeline.id.toString()
                        echo "Reusing existing pipeline record: ${env.PIPELINE_ID}"
                    } else {
                        def pipelinePayload = [
                            provider    : 'JENKINS',
                            jobName     : env.JOB_NAME,
                            buildNumber : env.BUILD_NUMBER.toInteger(),
                            branch      : env.BRANCH_NAME ?: 'master',
                            commitSha   : env.GIT_COMMIT ?: ''
                        ]

                        writeFile(
                            file: 'pipeline-payload.json',
                            text: JsonOutput.toJson(pipelinePayload)
                        )

                        def createPipelineJson = sh(
                            returnStdout: true,
                            script: """
                                set +x
                                curl --fail --silent --show-error \
                                  -X POST \
                                  -H "X-API-Key: \$SECUREOPS_API_KEY" \
                                  -H 'Content-Type: application/json' \
                                  --data-binary @pipeline-payload.json \
                                  '${env.SECUREOPS_URL}/api/projects/${env.PROJECT_ID}/pipelines'
                            """
                        ).trim()

                        def createdPipeline = readJSON(
                            text: createPipelineJson,
                            returnPojo: true
                        )

                        if (!createdPipeline.id) {
                            error('SecureOps did not return the created pipeline ID.')
                        }

                        env.PIPELINE_ID = createdPipeline.id.toString()
                    }

                    // Create one scan for this build.
                    def scanPayload = [
                        pipelineId : env.PIPELINE_ID,
                        environment: env.SCAN_ENVIRONMENT
                    ]

                    writeFile(
                        file: 'scan-payload.json',
                        text: JsonOutput.toJson(scanPayload)
                    )

                    def createScanJson = sh(
                        returnStdout: true,
                        script: """
                            set +x
                            curl --fail --silent --show-error \
                              -X POST \
                              -H "X-API-Key: \$SECUREOPS_API_KEY" \
                              -H 'Content-Type: application/json' \
                              --data-binary @scan-payload.json \
                              '${env.SECUREOPS_URL}/api/projects/${env.PROJECT_ID}/scans'
                        """
                    ).trim()

                    def createdScan = readJSON(
                        text: createScanJson,
                        returnPojo: true
                    )

                    if (!createdScan.id) {
                        error('SecureOps did not return the scan ID.')
                    }

                    env.SCAN_ID = createdScan.id.toString()

                    echo "Pipeline ID: ${env.PIPELINE_ID}"
                    echo "Scan ID: ${env.SCAN_ID}"
                }
            }
        }

        stage('5. Upload Trivy Report') {
            steps {
                script {
                    def uploadJson = sh(
                        returnStdout: true,
                        script: """
                            set +x
                            curl --fail --silent --show-error \
                              -X POST \
                              -H "X-API-Key: \$SECUREOPS_API_KEY" \
                              -F 'file=@trivy-report.json;type=application/json' \
                              '${env.SECUREOPS_URL}/api/scans/${env.SCAN_ID}/reports?tool=TRIVY'
                        """
                    ).trim()

                    def uploadedReport = readJSON(
                        text: uploadJson,
                        returnPojo: true
                    )

                    def reportId = uploadedReport.reportId ?: uploadedReport.id

                    if (!reportId) {
                        error("SecureOps did not return a report ID. Response: ${uploadJson}")
                    }

                    env.REPORT_ID = reportId.toString()

                    echo "Report uploaded: ${env.REPORT_ID}"
                    echo "Initial report status: ${uploadedReport.status}"
                }
            }
        }

        stage('6. Process Security Report') {
            steps {
                script {
                    def processJson = sh(
                        returnStdout: true,
                        script: """
                            set +x
                            curl --fail --silent --show-error \
                              -X POST \
                              -H "X-API-Key: \$SECUREOPS_API_KEY" \
                              '${env.SECUREOPS_URL}/api/scans/${env.SCAN_ID}/reports/${env.REPORT_ID}/process'
                        """
                    ).trim()

                    def processResult = readJSON(
                        text: processJson,
                        returnPojo: true
                    )

                    echo "Report processing response: ${processJson}"

                    if (processResult.status == 'FAILED') {
                        error('SecureOps reported that report processing failed.')
                    }

                    // Wait for asynchronous report processing.
                    def processed = false

                    for (int attempt = 1; attempt <= 24; attempt++) {
                        def reportJson = sh(
                            returnStdout: true,
                            script: """
                                set +x
                                curl --fail --silent --show-error \
                                  -H "X-API-Key: \$SECUREOPS_API_KEY" \
                                  '${env.SECUREOPS_URL}/api/reports/${env.REPORT_ID}'
                            """
                        ).trim()

                        def reportStatus = readJSON(
                            text: reportJson,
                            returnPojo: true
                        )

                        echo "Report status, attempt ${attempt}: ${reportStatus.status}"

                        if (reportStatus.status == 'PROCESSED') {
                            processed = true
                            break
                        }

                        if (reportStatus.status == 'FAILED') {
                            error("SecureOps failed to process report ${env.REPORT_ID}.")
                        }

                        sleep time: 5, unit: 'SECONDS'
                    }

                    if (!processed) {
                        error('Timed out waiting for SecureOps to process the Trivy report.')
                    }

                    echo 'Security report successfully processed.'
                }
            }
        }

        stage('7. Evaluate Security Policy') {
            steps {
                script {
                    def decisionReceived = false
                    def decisionData = null

                    for (int attempt = 1; attempt <= 12; attempt++) {
                        def httpCode = sh(
                            returnStdout: true,
                            script: """
                                set +x
                                curl --silent --show-error \
                                  -H "X-API-Key: \$SECUREOPS_API_KEY" \
                                  -o decision-response.json \
                                  -w '%{http_code}' \
                                  '${env.SECUREOPS_URL}/api/scans/${env.SCAN_ID}/decision'
                            """
                        ).trim()

                        if (httpCode == '200') {
                            def responseText = readFile(
                                file: 'decision-response.json'
                            ).trim()

                            decisionData = readJSON(
                                text: responseText,
                                returnPojo: true
                            )

                            if (decisionData.decision) {
                                decisionReceived = true
                                break
                            }
                        } else {
                            echo "Decision not ready yet (HTTP ${httpCode}), attempt ${attempt}."
                        }

                        sleep time: 5, unit: 'SECONDS'
                    }

                    if (!decisionReceived) {
                        error('No valid SecureOps security decision was received. Failing closed.')
                    }

                    env.DECISION = decisionData.decision.toString()

                    echo '========== SECUREOPS SECURITY DECISION =========='
                    echo "Decision: ${decisionData.decision}"
                    echo "Risk Score: ${decisionData.riskScore}"
                    echo "Critical: ${decisionData.criticalCount}"
                    echo "High: ${decisionData.highCount}"
                    echo "Medium: ${decisionData.mediumCount}"
                    echo "Low: ${decisionData.lowCount}"
                    echo "Reason: ${decisionData.reason}"
                    echo '================================================='

                    if (env.DECISION != 'PASS' && env.DECISION != 'BLOCK') {
                        error("Unknown security decision '${env.DECISION}'. Failing closed.")
                    }
                }
            }
        }

        stage('8. Enforce Security Gate') {
            steps {
                script {
                    if (env.DECISION == 'BLOCK') {
                        error('SECUREOPS BLOCKED THIS BUILD. Fix the security findings and rerun.')
                    }

                    echo 'SECUREOPS PASSED. Build is approved by the security policy.'
                }
            }
        }
    }

    post {
        success {
            echo "SecureOps pipeline completed successfully. Decision: ${env.DECISION}"
        }

        failure {
            echo 'SecureOps pipeline failed. Review the stage logs and security decision.'
        }

        always {
            echo "Build: ${env.BUILD_NUMBER}"
            echo "Project ID: ${env.PROJECT_ID ?: 'not registered'}"
            echo "Scan ID: ${env.SCAN_ID ?: 'not created'}"
            echo "Report ID: ${env.REPORT_ID ?: 'not uploaded'}"
            echo "Decision: ${env.DECISION ?: 'not received'}"
        }
    }
}
