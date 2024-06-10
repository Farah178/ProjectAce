pipeline {
    agent any

    environment {
        DOCKER_REGISTRY_URL = 'ekfrazoace.azurecr.io'
        DOCKER_REGISTRY_CREDENTIALS_ID = 'jenkinsaz'
        DOCKER_IMAGE_NAME = 'projectaceprod'
        REPO_URL = 'https://github.com/Farah178/ProjectAce.git'
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
                    sh 'az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant 9f939d94-0007-42c6-b87d-0a52cf98b86c'
                }
            }
        }

        stage('Push Docker Image to ACR') {
            steps {
                script {
                    docker.withRegistry("https://${env.DOCKER_REGISTRY_URL}", env.DOCKER_REGISTRY_CREDENTIALS_ID) {
                        def image = docker.image("${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}")
                        image.push()
                    }
                }
                script {
                    sh "docker tag ${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID} ${env.DOCKER_REGISTRY_URL}/${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}"
                    sh "docker push ${env.DOCKER_REGISTRY_URL}/${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}"
                }
            }
        }

        stage('Clean Up') {
            steps {
                sh "docker rmi ${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}"
                sh "docker rmi ${env.DOCKER_REGISTRY_URL}/${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}"
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
