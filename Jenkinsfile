import groovy.json.JsonOutput
import java.net.URLEncoder

pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 50, unit: 'MINUTES')
    }

    environment {
        SECUREOPS_URL = 'http://host.docker.internal:8081'
        PROJECT_NAME = 'Jenkins-Integration-Test-For-SecureOpsAI'
        REPOSITORY_URL = 'https://github.com/AyaanB24/Jenkins-Integration-Test-For-SecureOpsAI'
        SECURITY_ENV = 'DEVELOPMENT'
        TRIVY_CACHE = '/var/jenkins_home/trivy-cache'
        IMAGE_NAME = "secureops-demo:${BUILD_NUMBER}"
    }

    stages {
        stage('Build Docker Image') {
            steps {
                sh '''
                    set -eu
                    docker version
                    docker build -t "$IMAGE_NAME" .
                    docker image inspect "$IMAGE_NAME" >/dev/null
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

        stage('Register Build with SecureOps') {
            steps {
                script {
                    // HTTP helper: return status and response body.
                    def request = { method, url, payload = null ->
                        def suffix = UUID.randomUUID().toString()
                        def bodyFile = "secureops-response-${suffix}.json"
                        def requestFile = "secureops-request-${suffix}.json"

                        if (payload != null) {
                            writeFile(
                                file: requestFile,
                                text: JsonOutput.toJson(payload)
                            )
                        }

                        def command = """#!/bin/sh
set -eu
curl -sS --max-time 30 \
  -o '${bodyFile}' \
  -w '%{http_code}' \
  -X '${method}' \
  '${url}' \
  ${payload != null ?
      "-H 'Content-Type: application/json' --data-binary '@${requestFile}'" : ""}
"""

                        def statusText = sh(
                            script: command,
                            returnStdout: true
                        ).trim()

                        def responseBody = fileExists(bodyFile) ?
                            readFile(bodyFile) : ''

                        if (fileExists(bodyFile)) {
                            sh "rm -f '${bodyFile}'"
                        }
                        if (fileExists(requestFile)) {
                            sh "rm -f '${requestFile}'"
                        }

                        return [
                            status: statusText.toInteger(),
                            body: responseBody
                        ]
                    }

                    // 1. Find the project already registered in SecureOps.
                    def encodedName = URLEncoder.encode(
                        env.PROJECT_NAME, 'UTF-8'
                    )

                    def projectResponse = request(
                        'GET',
                        "${env.SECUREOPS_URL}/api/projects?name=${encodedName}"
                    )

                    if (projectResponse.status != 200) {
                        error(
                            "Project lookup failed: HTTP " +
                            "${projectResponse.status}: ${projectResponse.body}"
                        )
                    }

                    def project = readJSON text: projectResponse.body

                    if (!project.id) {
                        error('SecureOps project response has no ID.')
                    }

                    if (project.name != env.PROJECT_NAME) {
                        error('SecureOps returned a different project.')
                    }

                    if (project.repositoryUrl &&
                        project.repositoryUrl.replaceAll('/+$', '') !=
                        env.REPOSITORY_URL.replaceAll('/+$', '')) {
                        error('Registered repository URL does not match.')
                    }

                    env.SECUREOPS_PROJECT_ID = project.id.toString()
                    echo "Verified SecureOps project: ${project.name}"

                    // 2. Look for a pipeline record for this Jenkins build.
                    def pipelinesResponse = request(
                        'GET',
                        "${env.SECUREOPS_URL}/api/projects/" +
                        "${project.id}/pipelines"
                    )

                    if (pipelinesResponse.status != 200) {
                        error(
                            "Pipeline lookup failed: HTTP " +
                            "${pipelinesResponse.status}: " +
                            "${pipelinesResponse.body}"
                        )
                    }

                    def pipelines = readJSON text: pipelinesResponse.body

                    def branch = (
                        env.BRANCH_NAME ?:
                        env.GIT_BRANCH ?:
                        'master'
                    ).replaceFirst('^origin/', '')

                    def commit = env.GIT_COMMIT
                    if (!commit) {
                        commit = sh(
                            script: 'git rev-parse HEAD',
                            returnStdout: true
                        ).trim()
                    }

                    def existingPipeline = pipelines.find {
                        it.jobName == env.JOB_NAME &&
                        it.buildNumber?.toString() ==
                            env.BUILD_NUMBER.toString()
                    }

                    def pipelineId

                    if (existingPipeline) {
                        pipelineId = existingPipeline.id
                        echo "Using existing pipeline record: ${pipelineId}"
                    } else {
                        def createPipeline = request(
                            'POST',
                            "${env.SECUREOPS_URL}/api/projects/" +
                            "${project.id}/pipelines",
                            [
                                provider: 'JENKINS',
                                jobName: env.JOB_NAME,
                                buildNumber: env.BUILD_NUMBER.toInteger(),
                                branch: branch,
                                commitSha: commit
                            ]
                        )

                        if (createPipeline.status != 201) {
                            error(
                                "Pipeline creation failed: HTTP " +
                                "${createPipeline.status}: " +
                                "${createPipeline.body}"
                            )
                        }

                        pipelineId = (
                            readJSON text: createPipeline.body
                        ).id
                    }

                    if (!pipelineId) {
                        error('SecureOps pipeline ID is missing.')
                    }

                    env.SECUREOPS_PIPELINE_ID = pipelineId.toString()
                    echo "SecureOps pipeline: ${pipelineId}"

                    // 3. Create a fresh scan for this build.
                    def createScan = request(
                        'POST',
                        "${env.SECUREOPS_URL}/api/projects/" +
                        "${project.id}/scans",
                        [
                            pipelineId: pipelineId.toString(),
                            environment: env.SECURITY_ENV
                        ]
                    )

                    if (createScan.status != 201) {
                        error(
                            "Scan creation failed: HTTP " +
                            "${createScan.status}: ${createScan.body}"
                        )
                    }

                    def scan = readJSON text: createScan.body

                    if (!scan.id) {
                        error('SecureOps scan response has no ID.')
                    }

                    env.SECUREOPS_SCAN_ID = scan.id.toString()
                    echo "Created SecureOps scan: ${scan.id}"
                }
            }
        }

        stage('Upload Trivy Report to SecureOps') {
            steps {
                script {
                    sh '''
                        set -eu
                        test -s "$WORKSPACE/trivy-report.json"
                    '''

                    def responseFile = 'secureops-upload-response.json'

                    def status = sh(
                        script: """#!/bin/sh
set -eu
curl -sS --max-time 120 \
  -o '${responseFile}' \
  -w '%{http_code}' \
  -X POST \
  "\${SECUREOPS_URL}/api/scans/\${SECUREOPS_SCAN_ID}/reports?tool=TRIVY" \
  -F "file=@\${WORKSPACE}/trivy-report.json"
""",
                        returnStdout: true
                    ).trim()

                    if (status.toInteger() != 201) {
                        def body = fileExists(responseFile) ?
                            readFile(responseFile) : ''
                        error(
                            "Report upload failed: HTTP ${status}: ${body}"
                        )
                    }

                    def uploaded = readJSON file: responseFile
                    sh "rm -f '${responseFile}'"

                    if (!uploaded.id) {
                        error('Upload response has no report ID.')
                    }

                    env.SECUREOPS_REPORT_ID = uploaded.id.toString()
                    echo "Report uploaded: ${uploaded.id}"
                }
            }
        }

        stage('Process Security Report') {
            steps {
                script {
                    def reportUrl =
                        "${env.SECUREOPS_URL}/api/reports/" +
                        "${env.SECUREOPS_REPORT_ID}"

                    // Trigger report processing.
                    def processFile = 'secureops-process-response.json'

                    def processStatus = sh(
                        script: """#!/bin/sh
set -eu
curl -sS --max-time 120 \
  -o '${processFile}' \
  -w '%{http_code}' \
  -X POST \
  "\${SECUREOPS_URL}/api/scans/\${SECUREOPS_SCAN_ID}/reports/\${SECUREOPS_REPORT_ID}/process"
""",
                        returnStdout: true
                    ).trim()

                    def processBody = fileExists(processFile) ?
                        readFile(processFile) : ''

                    if (fileExists(processFile)) {
                        sh "rm -f '${processFile}'"
                    }

                    if (processStatus.toInteger() != 200) {
                        error(
                            "Report processing failed: HTTP " +
                            "${processStatus}: ${processBody}"
                        )
                    }

                    echo "Report processing triggered: ${processBody}"

                    timeout(time: 5, unit: 'MINUTES') {
                        waitUntil {
                            def responseFile =
                                'secureops-report-status.json'

                            def status = sh(
                                script: """#!/bin/sh
set -eu
curl -sS --max-time 20 \
  -o '${responseFile}' \
  -w '%{http_code}' \
  '${reportUrl}'
""",
                                returnStdout: true
                            ).trim()

                            if (status.toInteger() != 200) {
                                error(
                                    "Cannot retrieve report status: HTTP ${status}"
                                )
                            }

                            def report = readJSON file: responseFile
                            sh "rm -f '${responseFile}'"

                            if (report.status == 'FAILED') {
                                error('SecureOps report processing failed.')
                            }

                            if (report.status == 'PROCESSED') {
                                echo 'SecureOps report is PROCESSED.'
                                return true
                            }

                            if (!(report.status in ['RECEIVED', 'PROCESSING'])) {
                                error(
                                    "Unexpected report status: ${report.status}"
                                )
                            }

                            sleep(time: 3, unit: 'SECONDS')
                            return false
                        }
                    }
                }
            }
        }

        stage('Enforce SecureOps Decision') {
            steps {
                script {
                    def decisionUrl =
                        "${env.SECUREOPS_URL}/api/scans/" +
                        "${env.SECUREOPS_SCAN_ID}/decision"

                    def decision = null

                    timeout(time: 2, unit: 'MINUTES') {
                        waitUntil {
                            def responseFile =
                                'secureops-decision-response.json'

                            def status = sh(
                                script: """#!/bin/sh
set -eu
curl -sS --max-time 20 \
  -o '${responseFile}' \
  -w '%{http_code}' \
  '${decisionUrl}'
""",
                                returnStdout: true
                            ).trim()

                            def body = fileExists(responseFile) ?
                                readFile(responseFile) : ''

                            if (fileExists(responseFile)) {
                                sh "rm -f '${responseFile}'"
                            }

                            if (status.toInteger() == 404) {
                                echo 'Decision not available yet; retrying.'
                                sleep(time: 3, unit: 'SECONDS')
                                return false
                            }

                            if (status.toInteger() != 200) {
                                error(
                                    "Decision request failed: HTTP " +
                                    "${status}: ${body}"
                                )
                            }

                            decision = readJSON text: body

                            if (!(decision.decision in ['PASS', 'BLOCK'])) {
                                error(
                                    "Invalid SecureOps decision: " +
                                    "${decision.decision}"
                                )
                            }

                            return true
                        }
                    }

                    echo """
SecureOps Security Decision
Scan: ${decision.scanId}
Decision: ${decision.decision}
Risk Score: ${decision.riskScore}
Critical: ${decision.criticalCount}
High: ${decision.highCount}
Medium: ${decision.mediumCount}
Low: ${decision.lowCount}
Reason: ${decision.reason}
"""

                    env.SECUREOPS_DECISION = decision.decision.toString()

                    if (decision.decision == 'BLOCK') {
                        error(
                            "SECUREOPS BLOCKED this build: ${decision.reason}"
                        )
                    }

                    echo 'SECUREOPS PASS: security gate passed.'
                }
            }
        }
    }

    post {
        success {
            echo 'Build and SecureOps security gate succeeded.'
        }
        failure {
            echo 'Build failed or SecureOps rejected/failed the security check.'
        }
        always {
            echo 'SecureOps integration pipeline finished.'
        }
    }
}
```
