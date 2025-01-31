<div align="center">
<img alt="Docker Image Version (tag)" src="https://img.shields.io/docker/v/maxldwg/bicep-slips/latest?style=for-the-badge&logo=docker&label=Latest%20Version&link=https%3A%2F%2Fhub.docker.com%2Fr%2Fmaxldwg%2Fbicep-slips">
<img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/maxldwg/bicep-slips?style=for-the-badge&logo=docker&logoColor=blue&link=https%3A%2F%2Fhub.docker.com%2Fr%2Fmaxldwg%2Fbicep-slips">

<br>

</div>

# BICEP-slips-image
Slips image adapted for BICEP 


The image holds every dependency necessary along with the necessary interface implemented, in order to work with the BICEP application

The main BICEP project is available [here](https://github.com/maldwg/BICEP/tree/main)

## Initialize project

In order to be able to start the project you will need to initialize it first. Do this by running:

```
git submodule update --init --recursive
```
This fetches the newest version of the submodule for the backend code and is necessary for the application to work seamlessly.


## Building the project
TO build a local version of the image for testing purposes, simply run:
``` 
cd ./bicep-slips
docker buildx build . --build-arg BASE_IMAGE=stratosphereips/slips --build-arg VERSION=1.1.2 -t maxldwg/bicep-slips:latest --no-cache
```
Change the version to your desried one