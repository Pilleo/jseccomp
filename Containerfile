FROM eclipse-temurin:25-jdk

# Set up work directory
WORKDIR /workspace

# Install common utilities
RUN apt-get update && apt-get install -y \
    curl \
    git \
    strace \
    unzip \
    zsh \
    && rm -rf /var/lib/apt/lists/*

# The project uses Gradle Toolchains to download Java 25.
# Ensure the container has enough permissions to download and install toolchains.
ENV GRADLE_USER_HOME=/workspace/.gradle_home

# Default command
CMD ["./gradlew", "test"]
