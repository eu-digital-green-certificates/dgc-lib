FROM maven:3.8.1-adoptopenjdk-11

COPY . .

ENTRYPOINT ["mvn", "clean", "test"]