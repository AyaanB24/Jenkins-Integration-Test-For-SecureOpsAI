#!/usr/bin/env groovy
/*
 * SecureOps AI - Phase 11 Jenkinsfile
 *
 * Requirements:
 * - Docker CLI configured for the existing TLS-enabled Docker daemon.
 * - Trivy CLI installed in the Jenkins agent/container.
 * - Jenkins credential ID "secureops-url" contains the backend base URL reachable from Jenkins.
 * - Pipeline Utility Steps and HTTP Request plugins installed.
 *
 * Trivy scans a Docker image archive from the workspace, avoiding Docker socket
 * mounts and report-file sharing with a separate Trivy container.
 */

pipeline {
    agent any
    options {
        timestamps()
        timeout(time: 1, unit: 'HOURS')
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }
    environment {
        IMAGE_NAME = "secureops-demo:${BUILD_NUMBER}"
        SECUREOPS_URL = credentials('secureops-url')
        RETRY_DELAY_SECONDS = '3'
        REPORT_POLL_TIMEOUT = '90'
        DECISION_POLL_TIMEOUT = '90'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                echo 'Source checked out.'
            }
        }

        stage('Build Image') {
            steps {
                sh '''
                    set -eu
                    docker build -t "$IMAGE_NAME" .
                    docker save "$IMAGE_NAME" -o image.tar
                    test -s image.tar
                '''
            }
        }

        stage('Trivy Scan') {
            steps {
                sh '''
                    set -eu
                    command -v trivy >/dev/null 2>&1 || {
                      echo "ERROR: Trivy CLI is not installed in this Jenkins agent."
                      exit 1
                    }
                    trivy image --input image.tar --format json --output trivy-report.json
                    test -s trivy-report.json
                '''
                script {
                    def report = readJSON file: 'trivy-report.json'
                    if (!(report instanceof Map)) {
                        error 'Trivy report is not a valid JSON object.'
                    }
                    echo 'Trivy report generated and validated.'
                }
            }
        }

        stage('Register Project, Pipeline and Scan') {
            steps {
                script {
                    String baseUrl = env.SECUREOPS_URL.replaceAll('/+$', '')
                    String projectName = env.JOB_NAME
                        .replaceAll('[^a-zA-Z0-9-]', '-')
                        .replaceAll('-+', '-')
                        .replaceAll('^-|-$', '')
                        .toLowerCase()
                    if (!projectName) error 'Could not derive project name from JOB_NAME.'

                    def lookup = httpRequest(
                        httpMode: 'GET',
                        url: "${baseUrl}/api/projects?name=${java.net.URLEncoder.encode(projectName, 'UTF-8')}",
                        validResponseCodes: '200,404',
                        timeout: 20,
                        consoleLogResponseBody: false
                    )

                    def projectId = null
                    if (lookup.status == 200) {
                        def body = readJSON text: lookup.content
                        if (body instanceof List) {
                            projectId = body.find { it instanceof Map && it.name?.toString() == projectName }?.id
                        } else if (body instanceof Map) {
                            projectId = body.id ?: body.data?.id
                            if (!projectId && body.projects instanceof List) {
                                projectId = body.projects.find { it instanceof Map && it.name?.toString() == projectName }?.id
                            }
                        }
                        if (!projectId) {
                            error 'Project lookup returned HTTP 200 but no project ID. Check the actual backend response shape.'
                        }
                    } else {
                        def create = httpRequest(
                            httpMode: 'POST',
                            url: "${baseUrl}/api/projects",
                            contentType: 'APPLICATION_JSON',
                            requestBody: groovy.json.JsonOutput.toJson([
                                name: projectName,
                                repositoryUrl: (env.GIT_URL ?: 'unknown')
                            ]),
                            validResponseCodes: '200,201',
                            timeout: 20,
                            consoleLogResponseBody: false
                        )
                        def created = readJSON text: create.content
                        projectId = (created instanceof Map) ? (created.id ?: created.data?.id) : null
                        if (!projectId) error 'Project creation response did not contain an id field.'
                    }
                    env.PROJECT_ID = projectId.toString()
                    echo "SecureOps project: ${env.PROJECT_ID}"

                    def pipelineResult = httpRequest(
                        httpMode: 'POST',
                        url: "${baseUrl}/api/projects/${env.PROJECT_ID}/pipelines",
                        contentType: 'APPLICATION_JSON',
                        requestBody: groovy.json.JsonOutput.toJson([
                            provider: 'JENKINS',
                            jobName: env.JOB_NAME,
                            buildNumber: env.BUILD_NUMBER.toInteger(),
                            branch: (env.BRANCH_NAME ?: env.GIT_BRANCH ?: 'unknown'),
                            commitSha: (env.GIT_COMMIT ?: 'unknown')
                        ]),
                        validResponseCodes: '200,201,409',
                        timeout: 20,
                        consoleLogResponseBody: false
                    )

                    def pipelineId = null
                    if (pipelineResult.status in [200, 201]) {
                        def p = readJSON text: pipelineResult.content
                        pipelineId = (p instanceof Map) ? (p.id ?: p.data?.id) : null
                    } else {
                        def listResult = httpRequest(
                            httpMode: 'GET',
                            url: "${baseUrl}/api/projects/${env.PROJECT_ID}/pipelines",
                            validResponseCodes: '200',
                            timeout: 20,
                            consoleLogResponseBody: false
                        )
                        def listed = readJSON text: listResult.content
                        List items = listed instanceof List ? listed :
                            (listed instanceof Map && listed.pipelines instanceof List ? listed.pipelines :
                            (listed instanceof Map && listed.data instanceof List ? listed.data : []))
                        def match = items.find {
                            it instanceof Map &&
                            it.jobName?.toString() == env.JOB_NAME &&
                            it.buildNumber?.toString() == env.BUILD_NUMBER
                        }
                        pipelineId = match?.id
                        if (!pipelineId) {
                            error "Pipeline creation returned HTTP ${pipelineResult.status}; no exact matching pipeline was found. Check backend duplicate behavior."
                        }
                    }
                    if (!pipelineId) error 'Pipeline response did not contain an id field.'
                    env.PIPELINE_ID = pipelineId.toString()

                    def scanResult = httpRequest(
                        httpMode: 'POST',
                        url: "${baseUrl}/api/projects/${env.PROJECT_ID}/scans",
                        contentType: 'APPLICATION_JSON',
                        requestBody: groovy.json.JsonOutput.toJson([
                            pipelineId: env.PIPELINE_ID,
                            environment: 'PRODUCTION'
                        ]),
                        validResponseCodes: '200,201',
                        timeout: 20,
                        consoleLogResponseBody: false
                    )
                    def scanJson = readJSON text: scanResult.content
                    def scanId = (scanJson instanceof Map) ? (scanJson.id ?: scanJson.data?.id) : null
                    if (!scanId) error 'Scan creation response did not contain an id field.'
                    env.SCAN_ID = scanId.toString()
                    echo "SecureOps scan: ${env.SCAN_ID}"
                }
            }
        }

        stage('Upload Report') {
            steps {
                script {
                    String baseUrl = env.SECUREOPS_URL.replaceAll('/+$', '')
                    def result = httpRequest(
                        httpMode: 'POST',
                        url: "${baseUrl}/api/scans/${env.SCAN_ID}/reports?tool=TRIVY",
                        uploadFile: 'trivy-report.json',
                        multipartName: 'file',
                        validResponseCodes: '200,201',
                        timeout: 60,
                        consoleLogResponseBody: false
                    )
                    def reportJson = readJSON text: result.content
                    def reportId = (reportJson instanceof Map) ? (reportJson.id ?: reportJson.data?.id) : null
                    if (!reportId) error 'Report upload response did not contain an id field.'
                    env.REPORT_ID = reportId.toString()
                    echo "SecureOps report: ${env.REPORT_ID}"
                }
            }
        }

        stage('Process and Verify Report') {
            steps {
                script {
                    String baseUrl = env.SECUREOPS_URL.replaceAll('/+$', '')
                    def processResult = httpRequest(
                        httpMode: 'POST',
                        url: "${baseUrl}/api/scans/${env.SCAN_ID}/reports/${env.REPORT_ID}/process",
                        validResponseCodes: '200,202,204',
                        timeout: 30,
                        consoleLogResponseBody: false
                    )
                    echo "Report process endpoint returned HTTP ${processResult.status}."

                    long deadline = System.currentTimeMillis() + env.REPORT_POLL_TIMEOUT.toLong() * 1000
                    boolean processed = false
                    while (System.currentTimeMillis() < deadline) {
                        def result = httpRequest(
                            httpMode: 'GET',
                            url: "${baseUrl}/api/reports/${env.REPORT_ID}",
                            validResponseCodes: '200',
                            timeout: 20,
                            consoleLogResponseBody: false
                        )
                        def r = readJSON text: result.content
                        if (!(r instanceof Map) || !r.status) {
                            error 'Report status response is missing status; refusing to continue.'
                        }
                        String status = r.status.toString().toUpperCase()
                        if (status == 'PROCESSED') {
                            processed = true
                            break
                        }
                        if (status == 'FAILED') error 'SecureOps report processing failed.'
                        if (!(status in ['RECEIVED', 'PROCESSING', 'PENDING'])) {
                            error "Unknown report status '${status}'; refusing to continue."
                        }
                        echo "Report status: ${status}; waiting..."
                        sleep time: env.RETRY_DELAY_SECONDS.toInteger(), unit: 'SECONDS'
                    }
                    if (!processed) error "Report processing timed out after ${env.REPORT_POLL_TIMEOUT} seconds."
                }
            }
        }

        stage('Retrieve Decision') {
            steps {
                script {
                    String baseUrl = env.SECUREOPS_URL.replaceAll('/+$', '')
                    long deadline = System.currentTimeMillis() + env.DECISION_POLL_TIMEOUT.toLong() * 1000

                    while (System.currentTimeMillis() < deadline) {
                        def result = httpRequest(
                            httpMode: 'GET',
                            url: "${baseUrl}/api/scans/${env.SCAN_ID}/decision",
                            validResponseCodes: '200,404',
                            timeout: 20,
                            consoleLogResponseBody: false
                        )
                        if (result.status == 200) {
                            def decisionJson = readJSON text: result.content
                            if (!(decisionJson instanceof Map) || !decisionJson.decision) {
                                error 'Decision response is missing decision; refusing to continue.'
                            }
                            String value = decisionJson.decision.toString().toUpperCase()
                            if (!(value in ['PASS', 'BLOCK'])) {
                                error "Unknown decision '${value}'; refusing to continue."
                            }
                            env.DECISION = value
                            env.RISK_SCORE = decisionJson.riskScore?.toString() ?: 'N/A'
                            env.REASON = decisionJson.reason?.toString() ?: 'No reason provided'
                            break
                        }
                        echo 'Decision not available yet; waiting...'
                        sleep time: env.RETRY_DELAY_SECONDS.toInteger(), unit: 'SECONDS'
                    }

                    if (!env.DECISION) error "No decision within ${env.DECISION_POLL_TIMEOUT} seconds."
                }
            }
        }

        stage('Enforce Policy') {
            steps {
                script {
                    echo "Decision: ${env.DECISION}; risk score: ${env.RISK_SCORE}; reason: ${env.REASON}"
                    if (env.DECISION != 'PASS') {
                        error "Build blocked by SecureOps AI: ${env.REASON}"
                    }
                    echo 'PASS: policy satisfied. Deployment may be added after this stage.'
                }
            }
        }
    }

    post {
        always {
            sh '''
                docker rmi "$IMAGE_NAME" >/dev/null 2>&1 || true
                rm -f image.tar trivy-report.json
            '''
        }
        failure {
            script {
                if (env.SCAN_ID) echo "Build failed. SecureOps scan ID: ${env.SCAN_ID}"
            }
        }
        success {
            script {
                if (env.SCAN_ID) echo "Build succeeded. SecureOps scan ID: ${env.SCAN_ID}"
            }
        }
    }
}
