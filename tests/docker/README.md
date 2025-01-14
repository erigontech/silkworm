This docker setup is designed to provide a consistent environment for running tests and building the project. 

It is made of two parts. The first part downloads the project into a docker container, installs all the dependencies, configures the packages and builds all the binaries. This part is cached so that it doesn't have to be run every time.
In the second part, an up-to-date version of the project is downloaded into a new container and the build is run again. This guarantees the quickness of the build.

To build and run docker image simply run:
```bash
./run-docker.sh master
```

You can also run the docker image with a specific branch or tag:
```bash
./run-docker.sh my-branch
```

From time to time it is necessary to rebuild the whole docker image and refresh any cached parts. To do so, run:
```bash
./run-docker.sh -r master
```
Inside the Dockerfile you can find a certain variations:
- build using different clang versions
- build using local changes
- run tests
- run fuzzer
To run them, simply uncomment or change the desired lines and run the script again.