pipeline {
    agent any

    environment {
        DOCKER_REGISTRY_URL = 'ekfrazoace.azurecr.io'
        DOCKER_REGISTRY_CREDENTIALS_ID = 'jenkinsaz'
        DOCKER_IMAGE_NAME = 'projectaceprod'
        REPO_URL = 'https://github.com/Farah178/ProjectAce.git'
        AZURE_TENANT_ID = '9f939d94-0007-42c6-b87d-0a52cf98b86c'
        KUBECONFIG_PATH = '/home/ubuntu/.kube/config'
        NAMESPACE = 'projectace'
    }

    stages {
        stage('Clone Repository') {
            steps {
                git branch: 'main', url: "${env.REPO_URL}"
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    docker.build("${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}")
                }
            }
        }

        stage('Login to Azure') {
            steps {
                withCredentials([usernamePassword(credentialsId: env.DOCKER_REGISTRY_CREDENTIALS_ID, usernameVariable: 'AZURE_CLIENT_ID', passwordVariable: 'AZURE_CLIENT_SECRET')]) {
                    sh "az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant ${AZURE_TENANT_ID}"
                }
            }
        }

        stage('Push Docker Image to ACR') {
    steps {
        script {
            // Retrieve credentials
            withCredentials([usernamePassword(credentialsId: env.DOCKER_REGISTRY_CREDENTIALS_ID, usernameVariable: 'DOCKER_USERNAME', passwordVariable: 'DOCKER_PASSWORD')]) {
                // Tag the image
                sh "docker tag ${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID} ${env.DOCKER_REGISTRY_URL}/${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}"

                // Authenticate Docker with ACR using the retrieved credentials
                sh "echo \$DOCKER_PASSWORD | docker login \$DOCKER_REGISTRY_URL --username \$DOCKER_USERNAME --password-stdin"

                // Push the image
                sh "docker push ${env.DOCKER_REGISTRY_URL}/${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}"
            }
        }
    }
}


        stage('Clean Up') {
            steps {
                script {
                    sh "docker rmi ${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}"
                    sh "docker rmi ${env.DOCKER_REGISTRY_URL}/${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}"
                }
            }
        }
        
        stage('Deploy to Kubernetes') {
            steps {
                script {
                    // Pull the latest image from ACR
                    sh "docker pull ${env.DOCKER_REGISTRY_URL}/${env.DOCKER_IMAGE_NAME}:latest"

                    // Deploy the image to Kubernetes
                    sh "kubectl apply -f deployment.yaml -n ${NAMESPACE}"
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
