
FROM jenkins/jenkins:lts-jdk21

USER root

RUN apt-get update -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowUnauthenticatedPackages=true && \
    apt-get install -y -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowUnauthenticatedPackages=true \
    ca-certificates curl gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
       -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && . /etc/os-release \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
       > /etc/apt/sources.list.d/docker.list \
    && curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
       | gpg --dearmor -o /etc/apt/keyrings/trivy.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
       > /etc/apt/sources.list.d/trivy.list \
    && apt-get update -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowUnauthenticatedPackages=true \
    && apt-get install -y -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowUnauthenticatedPackages=true docker-ce-cli trivy \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

USER jenkins

RUN jenkins-plugin-cli --plugins "docker-workflow"
