pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    environment {
        IMAGE_NAME = 'secureops-demo'
        REPORT_FILE = 'trivy-report.json'
        SECUREOPS_URL = credentials('secureops-backend-url')
        PROJECT_ID = 'REPLACE_WITH_EXISTING_PROJECT_ID'
    }

    stages {
        stage('Checkout & Build') {
            steps {
                checkout scm
                sh '''
                    docker build -t ${IMAGE_NAME}:${BUILD_NUMBER} .
                '''
            }
        }

        stage('Trivy Scan') {
            steps {
                sh '''
                    docker run --rm \
                      -v /var/run/docker.sock:/var/run/docker.sock \
                      -v "$WORKSPACE:/report" \
                      aquasecurity/trivy:latest image \
                      --format json \
                      --output /report/${REPORT_FILE} \
                      ${IMAGE_NAME}:${BUILD_NUMBER}

                    test -s "${REPORT_FILE}"
                '''
                archiveArtifacts artifacts: 'trivy-report.json',
                                 fingerprint: true
            }
        }

        stage('Submit to SecureOps') {
            steps {
                script {
                    def pipeline = sh(
                        script: '''
                            curl -fsS -X POST \
                              "$SECUREOPS_URL/api/projects/$PROJECT_ID/pipelines" \
                              -H "Content-Type: application/json" \
                              -d "{
                                \\"provider\\":\\"JENKINS\\",
                                \\"jobName\\":\\"$JOB_NAME\\",
                                \\"buildNumber\\":$BUILD_NUMBER,
                                \\"branch\\":\\"$BRANCH_NAME\\",
                                \\"commitSha\\":\\"$GIT_COMMIT\\"
                              }"
                        ''',
                        returnStdout: true
                    ).trim()

                    def p = new groovy.json.JsonSlurperClassic().parseText(pipeline)
                    if (!p.id) error('SecureOps did not return a pipeline ID')

                    def scan = sh(
                        script: """
                            curl -fsS -X POST \\
                              "$SECUREOPS_URL/api/projects/$PROJECT_ID/scans" \\
                              -H "Content-Type: application/json" \\
                              -d '{"pipelineId":"${p.id}","environment":"DEVELOPMENT"}'
                        """,
                        returnStdout: true
                    ).trim()

                    def s = new groovy.json.JsonSlurperClassic().parseText(scan)
                    if (!s.id) error('SecureOps did not return a scan ID')
                    env.SCAN_ID = s.id.toString()

                    def report = sh(
                        script: '''
                            curl -fsS -X POST \
                              "$SECUREOPS_URL/api/scans/$SCAN_ID/reports?tool=TRIVY" \
                              -F "file=@trivy-report.json"
                        ''',
                        returnStdout: true
                    ).trim()

                    def r = new groovy.json.JsonSlurperClassic().parseText(report)
                    if (!r.id) error('SecureOps did not return a report ID')

                    sh """
                        curl -fsS -X POST \\
                          "$SECUREOPS_URL/api/scans/$SCAN_ID/reports/${r.id}/process"
                    """
                }
            }
        }

        stage('Enforce Security Decision') {
            steps {
                script {
                    // Replace this fixed wait with polling of the real processing status.
                    sleep(time: 3, unit: 'SECONDS')

                    def response = sh(
                        script: '''
                            curl -fsS \
                              "$SECUREOPS_URL/api/scans/$SCAN_ID/decision"
                        ''',
                        returnStdout: true
                    ).trim()

                    def result =
                        new groovy.json.JsonSlurperClassic().parseText(response)

                    if (result.decision != 'PASS') {
                        error("SecureOps decision is not PASS: ${result.decision}")
                    }

                    echo "SecureOps PASS — Scan ID: ${SCAN_ID}"
                }
            }
        }
    }

    post {
        always {
            echo "Build result: ${currentBuild.currentResult}"
        }
    }
}