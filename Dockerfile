FROM maven:3.9-eclipse-temurin-25 AS builder
WORKDIR /app
COPY pom.xml ./
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -DskipTests -q

FROM eclipse-temurin:25-jre-alpine AS runtime
WORKDIR /app

RUN addgroup -g 10001 -S poc && adduser -u 10001 -S poc -G poc
USER poc

COPY --from=builder /app/target/*.jar app.jar

# CLI-Demo-Adapter: laeuft einmalig (verschluesseln/entschluesseln/signieren/verifizieren)
# und beendet sich danach - kein Langzeit-Server, daher kein EXPOSE/HEALTHCHECK.
ENTRYPOINT ["java", "-jar", "app.jar"]
