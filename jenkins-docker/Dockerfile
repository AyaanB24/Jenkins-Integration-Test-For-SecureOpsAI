FROM jenkins/jenkins:lts-jdk21

USER root

RUN apt-get update -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowUnauthenticatedPackages=true && \
    apt-get install -y -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowUnauthenticatedPackages=true \
    ca-certificates curl gnupg lsb-release wget \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
       -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
    -o /tmp/trivy-public.key \
    && gpg --dearmor -o /usr/share/keyrings/trivy.gpg /tmp/trivy-public.key \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
       > /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/* /tmp/trivy-public.key

USER jenkins

RUN jenkins-plugin-cli --plugins "docker-workflow"