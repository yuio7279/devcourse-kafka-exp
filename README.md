# Spring Cloud + Kafka 기반 사가패턴 아키텍처 학습 내용 정리
📘 **Kafka 로컬 설치 및 Docker Compose 클러스터 정리**

### 1. 로컬 실행 기본 명령어

```
./kafka-storage random-uuid     # ID 생성
./kafka-storage format -t [id] -c ../../config/server.properties --standalone
./kafka-server-start ../../config/server.properties
```

### 2. Docker 개요

* Docker는 내 환경을 **이미지화**해 다른 컴퓨터에서도 동일하게 실행하기 위해 만들어짐.
* 구조: **CLI → API → Daemon(서버)**
* Docker Desktop 실행 시 도커 데몬 자동 실행됨.

### 3. Kafka Docker 설정 절차

1. 작업 폴더에 `kafka` 폴더 생성
2. VS Code 또는 IntelliJ로 열기
3. `docker-compose.yml` 작성
4. `.env` 파일로 환경 변수 분리

---

## 🧩 Docker Compose 개념 요약

* 리눅스 커널 수준의 **컨테이너 가상화 기술** 위에서 동작
* 여러 컨테이너를 관리하기 위한 **오케스트레이션 도구**
* 설정 파일: `docker-compose.yml`

---

## 🧱 Single Node Kafka Compose 설정

```
name: kafka

services:
  kafka-1:
    image: apache/kafka
    ports:
      - "9092:9092"
    environment:
      - KAFKA_NODE_ID=1
      - CLUSTER_ID=FWnZMGJSQMWSy6uo0OKQTA
      - KAFKA_PROCESS_ROLES=controller,broker
      - KAFKA_CONTROLLER_QUORUM_VOTERS=1@kafka-1:9091
      - KAFKA_LISTENERS=PLAINTEXT://:9090,CONTROLLER://:9091,EXTERNAL://:9092
      - KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka-1:9090,EXTERNAL://${HOSTNAME:-localhost}:9092
      - KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT,PLAINTEXT:PLAINTEXT
      - KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER
      - KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT
```

### 환경변수 파일 (`environments.env`)

```
HOSTNAME=host.docker.internal
```

### 실행 명령

```
docker compose --env-file ./environments.env up -d
docker ps | grep kafka
```

### 컨테이너 접속

```
docker exec --workdir=/opt/kafka/bin -it kafka-kafka-1-1 bash
```

### 토픽 생성 및 확인

```
./kafka-topics.sh --create --topic test-topic --bootstrap-server host.docker.internal:9092
./kafka-topics.sh --list --bootstrap-server host.docker.internal:9092
```

---

## 🧭 Multi Node Kafka Cluster 설정

```
name: kafka

services:
  kafka-1:
    image: apache/kafka
    container_name: kafka-1
    ports:
      - "9092:9092"
    environment:
      - KAFKA_NODE_ID=1
      - CLUSTER_ID=QszDYpiURRaeCz86lsxokg
      - KAFKA_PROCESS_ROLES=controller,broker
      - KAFKA_CONTROLLER_QUORUM_VOTERS=1@kafka-1:9091,2@kafka-2:9091,3@kafka-3:9091
      - KAFKA_LISTENERS=PLAINTEXT://:9090,CONTROLLER://:9091,EXTERNAL://:9092
      - KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka-1:9090,EXTERNAL://localhost:9092
      - KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT,PLAINTEXT:PLAINTEXT
      - KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER
      - KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT

  kafka-2:
    image: apache/kafka
    container_name: kafka-2
    ports:
      - "9094:9094"
    environment:
      - KAFKA_NODE_ID=2
      - CLUSTER_ID=QszDYpiURRaeCz86lsxokg
      - KAFKA_PROCESS_ROLES=controller,broker
      - KAFKA_CONTROLLER_QUORUM_VOTERS=1@kafka-1:9091,2@kafka-2:9091,3@kafka-3:9091
      - KAFKA_LISTENERS=PLAINTEXT://:9090,CONTROLLER://:9091,EXTERNAL://:9094
      - KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka-2:9090,EXTERNAL://localhost:9094
      - KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT,PLAINTEXT:PLAINTEXT
      - KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER
      - KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT

  kafka-3:
    image: apache/kafka
    container_name: kafka-3
    ports:
      - "9096:9096"
    environment:
      - KAFKA_NODE_ID=3
      - CLUSTER_ID=QszDYpiURRaeCz86lsxokg
      - KAFKA_PROCESS_ROLES=controller,broker
      - KAFKA_CONTROLLER_QUORUM_VOTERS=1@kafka-1:9091,2@kafka-2:9091,3@kafka-3:9091
      - KAFKA_LISTENERS=PLAINTEXT://:9090,CONTROLLER://:9091,EXTERNAL://:9096
      - KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka-3:9090,EXTERNAL://localhost:9096
      - KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT,PLAINTEXT:PLAINTEXT
      - KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER
      - KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT
```

### 실행

```
docker compose up -d
docker exec --workdir=/opt/kafka/bin -it kafka-1 bash
```

### 토픽 생성 (멀티노드)

```
./kafka-topics.sh --create --topic test-topic2 --partitions 3 --replication-factor 2 --bootstrap-server localhost:9092
```

---

📚 **참고 문서**
[Kafka 공식문서 (KRaft 모드)](https://kafka.apache.org/documentation/#kraft_role)


📘 **Kafka Cluster + Microservice Architecture 정리 **

### 1. Docker 이미지 개념

* 컨테이너 실행 시 **이미지(.iso)** 필요
* `.iso`: 가상의 CD-ROM을 만들어 그 안의 OS나 소프트웨어를 부팅하는 형식
* Docker Hub = 원격 이미지 저장소(Registry)
  → 개인용 Registry 생성 가능
* 이미지 저장 위치: **image-registry**

### 2. Kafka 이미지 선택

* `bitnami/kafka`: 최신버전 보안 업데이트 중단 (유료 전환)
* `apache/kafka`: 공식 이미지 사용 (옆에 공식 로고 확인 필수)
* 불분명한 출처 이미지는 악성 코드 위험 있음
* 버전 확인: `tags > latest`

---

### 3. 클러스터 재시작 및 확인

```
docker compose down
docker compose up -d
docker ps | grep kafka
```

### 4. Kafka 컨테이너 접속

```
docker exec --workdir=/opt/kafka/bin -it kafka-2 bash
./kafka-topics.sh --list --bootstrap-server localhost:9094
```

* 클러스터링 테스트:
  1번 노드에서 생성한 토픽이 2, 3번 노드에 분배되어야 함.

---

## 🧱 토픽 생성 (3노드 클러스터)

```
./kafka-topics.sh \
  --create --topic topic2 \
  --partitions 3 \
  --replication-factor 3 \
  --bootstrap-server localhost:9092,localhost:9094,localhost:9096
```

### 토픽 조회 및 상세 확인

```
./kafka-topics.sh --list --bootstrap-server localhost:9092
./kafka-topics.sh --describe --bootstrap-server localhost:9092
```

---

## 💬 Kafka 메시지 송수신

### Producer (메시지 전송)

```
./kafka-console-producer.sh --bootstrap-server localhost:9092,localhost:9094 --topic topic2
```

### Consumer (메시지 수신)

```
./kafka-console-consumer.sh --topic topic2 --from-beginning --bootstrap-server localhost:9092
```

* `--from-beginning`: 과거 메시지까지 전체 출력

---

## 🔑 Key-Value 메시지 모드

### Producer (키-값 전송)

```
./kafka-console-producer.sh \
  --bootstrap-server localhost:9092 \
  --topic topic2 \
  --property "parse.key=true" \
  --property "key.separator=:"
```

* 메시지 예시:
  `productName:Product001`

### Consumer (키-값 표시)

```
./kafka-console-consumer.sh \
  --topic topic2 \
  --from-beginning \
  --bootstrap-server localhost:9092 \
  --property "print.key=true"
```

---

## 🧩 프로젝트 구조 설계 (Microservice 분리)

### 1. Core 모듈 생성

* 공통 로직 관리용 (`core`)
* Java 21 버전 맞추기
* `JPA` 의존 추가 이유: 코어 모듈이 빌드될 때 ORM 필요
* `Saga Pattern` 적용 위해 분리

#### Gradle 설정

`settings.gradle`

```
include(':core')
project(':core').projectDir = file('./core')
```

`build.gradle`

```
implementation project(':core')
```

* 상위 프로젝트와 **Spring Boot 버전 동일**하게 유지

---

## 🛰️ 서비스 구성

### 2. Discovery Service

```
@EnableEurekaServer
port: 8761
eureka:
  client:
    register-with-eureka: false
    fetch-registry: false
```

### 3. Gateway Service

* 이름: `gateway-service`
* 의존성: Reactive Gateway, Eureka Discovery Client
* 포트: `8000`

---

## 👥 Account Service (회원 서비스)

* 의존성:

  ```
  web, jpa, validation, security, eureka client, lombok, h2, jwt
  org.springframework.security:spring-security-crypto
  ```
* `vo.Role` → 공통 모듈(`core`)로 이동
* `PasswordEncoderConfiguration`

  ```
  @Bean
  public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
  }
  ```

---

## 🧠 Security 및 토큰 처리

* 인증과 회원은 **하나의 바운더리 컨텍스트**
* Security는 `account-service` 내부로 이동
* Gateway는 **인증 진입점**
  → 인증 성공 시 내부 서비스 호출 시 헤더(`X-CODE`) 추가
* `X-CODE`: JWT 기반 회원 코드
* 응답 시 헤더는 제외하고 일반 응답만 전달
* `TokenAuthenticationFilter` → Gateway로 이동

---

✅ **핵심 요약**

* Kafka 이미지: `apache/kafka` 사용
* Multi-node 클러스터 구축 후 replication 테스트
* 메시지 송수신 CLI 명령어 숙지
* Spring MSA 구성 시 `core`, `gateway`, `discovery`, `account` 모듈로 분리
* Gateway 단에서 인증 헤더(`X-CODE`) 관리


📘 **Gateway 필터 + JWT 인증 흐름 정리 (3차 필기)**

### 1. Gateway 역할

* 모든 요청은 **Gateway**를 단일 진입점으로 통과
* 요청이 들어오면 **필터(Filter)**에서

  1. JWT 토큰 판별
  2. 정보 추출
  3. 커스텀 헤더(`X-CODE`)에 추가
  4. 이후 서비스로 전달 (로드밸런싱)

---

## 🧩 2. JWT 적용

* 의존성: `io.jsonwebtoken:jjwt` (JJWT)
* 공식 RFC 문서 기반 (JWT 구조: Header + Payload + Signature)

**Gradle 예시**

```
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
```

---

## 🧱 3. TokenAuthenticationFilter (WebFlux용)

* 리액티브 기반 WebFlux 환경 →
  `AbstractGatewayFilterFactory<TokenAuthenticationFilter.Config>` 상속

**구조**

```java
@Component
public class TokenAuthenticationFilter extends AbstractGatewayFilterFactory<TokenAuthenticationFilter.Config> {

    public TokenAuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)
                && !request.getCookies().containsKey("token")) {
                return response.writeWith(
                    Flux.just(writeUnauthorizedResponseBody(response))
                );
            }

            // 이후 토큰 검증 및 헤더 추가 로직
            return chain.filter(exchange);
        };
    }
}
```

---

## ⚙️ 4. 인증 실패 응답 처리

```java
private DataBuffer writeUnauthorizedResponseBody(ServerHttpResponse response) {
    response.setStatusCode(HttpStatus.UNAUTHORIZED);
    response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");

    TokenAuthorizationResponse body = new TokenAuthorizationResponse("인증이 필요합니다.");

    ObjectMapper om = new ObjectMapper();
    byte[] bytes = om.writeValueAsBytes(body);

    return response.bufferFactory().wrap(bytes);
}
```

### 공통 Response 클래스 (`core/model/web/TokenAuthorizationResponse.java`)

```java
public record TokenAuthorizationResponse(String message) {}
```

**Core 모듈에 추가 후 설정**

```
settings.gradle → include(':core')
build.gradle → implementation project(':core')
```

---

## 🔒 5. JWT 유효성 검사 로직

* Bearer 토큰 확인
* JJWT로 파싱하여 Header, Payload, Signature 검증
* 만료 여부 확인

```java
private boolean isValidToken(String token) { ... }
private Jws<Claims> getClaims(String token) { ... }
```

**application.yml**

```
custom:
  jwt:
    secrets:
      app-key: [비밀키]
```

* `Claims`에서 `accountCode` 추출 후

  ```
  request.mutate()
         .header("X-CODE", accountCode)
         .build();
  return chain.filter(exchange.mutate().request(mutatedRequest).build());
  ```

---

## 🧭 6. 토큰 필요/불필요 경로 설정

**Gateway application.yml**

```
spring:
  cloud:
    gateway:
      server:
        webflux:
          routes:
            # Related to Auth
            - id: auth-sign-in
              uri: lb://ACCOUNTS-SERVICE
              predicates:
                - Path=/login
                - Method=POST
            - id: auth-sign-out
              uri: lb://ACCOUNTS-SERVICE
              predicates:
                - Path=/logout
                - Method=POST

            # Related to Account
            - id: accounts-service-public
              uri: lb://ACCOUNTS-SERVICE
              predicates:
                - Path=/accounts
            - id: accounts-sign-in
              uri: lb://ACCOUNTS-SERVICE
              predicates:
                - Path=/accounts
                - Method=POST
            - id: accounts-service-protected
              uri: lb://ACCOUNTS-SERVICE
              predicates:
                - Path=/accounts/**
                - Method=GET,POST,PATCH,PUT,DELETE
              filters:
                - TokenAuthenticationFilter

            # Related to Business
            - id: demo-service-protected-1
              uri: lb://DEMO-SERVICE
              predicates:
                - Path=/carts/**,/carts
              filters:
                - TokenAuthenticationFilter

            - id: demo-service-protected-2
              uri: lb://DEMO-SERVICE
              predicates:
                - Path=/**
                - Method=POST,PATCH,PUT,DELETE
              filters:
                - TokenAuthenticationFilter

            - id: demo-service-public
              uri: lb://DEMO-SERVICE
              predicates:
                - Path=/**
                - Method=GET
```

---

## 🧩 7. 의존성 전파 관리

* `implementation` → 하위 모듈로 전파됨
* `compileOnly` → 전파 안됨
  → Spring Security를 `compileOnly`로 변경해 의존성 격리

---

## 🧹 8. 불필요 코드 제거

* `dataInitializer` 삭제
* `demo` 프로젝트에서 시큐리티 제거

---

## ⚙️ 9. Eureka 설정

**공통 설정**

```
eureka:
  instance:
    instance-id: "${spring.application.name}:${server.port}:${random.uuid}"
```

* Gateway와 Demo 모두 적용
* Demo에 `Eureka Client` 의존성 추가
* Demo `resources/application.yml` 삭제

---

## 🧠 10. 인증 헤더 적용

* 인가가 필요한 API 호출 시 `X-CODE` 헤더 사용
* Gateway 필터에서 토큰 파싱 후 자동 삽입
* Postman 테스트:

  1. 회원가입
  2. 로그인
  3. 상품 생성 요청

🧩 1. Kafka 클러스터 구성 (docker-compose.yml)
```
name: kafka
services:
  kafka-1:
    image: apache/kafka
    container_name: kafka-1
    ports:
      - "9092:9092"
    environment:
      - KAFKA_NODE_ID=1
      - CLUSTER_ID=ZWU1Y2JiNDctNDg3ZC4tNGY2Ny1iNzJh
      - KAFKA_PROCESS_ROLES=controller,broker
      - KAFKA_CONTROLLER_QUORUM_VOTERS=1@kafka-1:9091,2@kafka-2:9091,3@kafka-3:9091
      - KAFKA_LISTENERS=PLAINTEXT://:9090,CONTROLLER://:9091,EXTERNAL://:9092
      - KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka-1:9090,EXTERNAL://localhost:9092
      - KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT,PLAINTEXT:PLAINTEXT
      - KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER
      - KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT

  kafka-2:
    image: apache/kafka
    container_name: kafka-2
    ports:
      - "9094:9094"
    environment:
      - KAFKA_NODE_ID=2
      - CLUSTER_ID=ZWU1Y2JiNDctNDg3ZC4tNGY2Ny1iNzJh
      - KAFKA_PROCESS_ROLES=controller,broker
      - KAFKA_CONTROLLER_QUORUM_VOTERS=1@kafka-1:9091,2@kafka-2:9091,3@kafka-3:9091
      - KAFKA_LISTENERS=PLAINTEXT://:9090,CONTROLLER://:9091,EXTERNAL://:9094
      - KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka-2:9090,EXTERNAL://localhost:9094
      - KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT,PLAINTEXT:PLAINTEXT
      - KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER
      - KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT

  kafka-3:
    image: apache/kafka
    container_name: kafka-3
    ports:
      - "9096:9096"
    environment:
      - KAFKA_NODE_ID=3
      - CLUSTER_ID=ZWU1Y2JiNDctNDg3ZC4tNGY2Ny1iNzJh
      - KAFKA_PROCESS_ROLES=controller,broker
      - KAFKA_CONTROLLER_QUORUM_VOTERS=1@kafka-1:9091,2@kafka-2:9091,3@kafka-3:9091
      - KAFKA_LISTENERS=PLAINTEXT://:9090,CONTROLLER://:9091,EXTERNAL://:9096
      - KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka-3:9090,EXTERNAL://localhost:9096
      - KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT,PLAINTEXT:PLAINTEXT
      - KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER
      - KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT

```
infra 폴더에서 실행:

docker compose up -d


추후 MariaDB 추가 예정.

🧠 2. Saga 개요

코레오그래피(Choreography) 기반 사가 패턴 사용

각 서비스가 이벤트로 반응하며 순차적 트랜잭션을 완성

Account-Service가 “조정자(Coordinator)” 역할 수행

Kafka 이벤트 흐름으로 서비스 간 결합도 최소화

⚙️ 3. Kafka 의존성 추가
implementation 'org.springframework.kafka:spring-kafka'


application.yml
```
spring:
  kafka:
    bootstrap-servers:
      - localhost:9092
      - localhost:9094
      - localhost:9096
    producer:
      key-serializer: org.apache.kafka.common.serialization.StringSerializer
      value-serializer: org.springframework.kafka.support.serializer.JsonSerializer
      acks: all
      properties:
        delivery.timeout.ms: 120000
        linger.ms: 0
        request.timeout.ms: 30000
        enable.idempotence: true
        allow.auto.create.topics: false

🧩 4. 토픽 생성 (Account-Service)
@Configuration
public class KafkaConfiguration {

    @Bean
    public NewTopic createAccountsEventTopic(
            @Value("${accounts.config.topic-partitions}") int partitions,
            @Value("${accounts.config.topic-replications}") short replications,
            @Value("${accounts.events.topic.name}") String topicName) {
        return TopicBuilder.name(topicName)
                .partitions(partitions)
                .replicas(replications)
                .build();
    }

    @Bean
    public KafkaTemplate<String, Object> kafkaTemplate(ProducerFactory<String, Object> factory) {
        return new KafkaTemplate<>(factory);
    }
}


yml

accounts:
  config:
    topic-partitions: 3
    topic-replications: 3
  events:
    topic:
      name: accounts-events
```
🧱 5. 이벤트 정의 (core 모듈)

core/events/AccountCreatedEvent.java
```
public record AccountCreatedEvent(String accountCode) {}
```
⚡ 6. 이벤트 발행 (Account-Service)
```
@Service
@RequiredArgsConstructor
public class AccountService {
    private final KafkaTemplate<String, Object> kafkaTemplate;
    @Value("${accounts.events.topic.name}")
    private String topicName;

    public Account createAccount(Account account) {
        // 계정 생성 로직
        AccountCreatedEvent event = new AccountCreatedEvent(account.getCode());
        kafkaTemplate.send(topicName, event);
        return account;
    }
}
```
🧭 7. Saga 리스너 (Account-Service)
```
@Component
@RequiredArgsConstructor
@KafkaListener(topics = {"${accounts.events.topic.name}"})
public class AccountSaga {
    private final KafkaTemplate<String, Object> kafkaTemplate;

    @KafkaHandler
    public void handle(@Payload AccountCreatedEvent event) {
        CreateCartCommand command = new CreateCartCommand(event.accountCode());
        kafkaTemplate.send("carts-commands", command);
    }
}
```
📦 8. Command 정의 (core/commands)
```
public record CreateCartCommand(String accountCode) {}
```
🛒 9. Demo-Service (Cart 처리 서비스)
```
application.yml

spring:
  kafka:
    bootstrap-servers:
      - localhost:9092
      - localhost:9094
      - localhost:9096
    consumer:
      group-id: demo-service
      key-deserializer: org.apache.kafka.common.serialization.StringDeserializer
      value-deserializer: org.springframework.kafka.support.serializer.JsonDeserializer
      properties:
        spring.json.trusted.packages: io.eddie.core.*
        allow.auto.create.topics: false
carts:
  command:
    topic:
      name: carts-commands
  events:
    topic:
      name: carts-events


Kafka 설정

@Configuration
public class KafkaConfiguration {
    @Bean
    public KafkaTemplate<String, Object> kafkaTemplate(ProducerFactory<String, Object> factory) {
        return new KafkaTemplate<>(factory);
    }

    @Bean
    public NewTopic cartsCommandsTopic(@Value("${carts.command.topic.name}") String topicName) {
        return TopicBuilder.name(topicName).partitions(3).replicas(3).build();
    }
}
```

🧩 10. 명령어 처리 핸들러 (Demo-Service)
```
@Component
@RequiredArgsConstructor
@KafkaListener(topics = {"${carts.command.topic.name}"})
public class CartsCommandsHandler {

    private final CartService cartService;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    @Value("${carts.events.topic.name}")
    private String cartsEventTopic;

    @KafkaHandler
    public void handleCommand(@Payload CreateCartCommand command) {
        try {
            cartService.createCart(command.accountCode());
            kafkaTemplate.send(cartsEventTopic, new CartCreatedEvent(command.accountCode(), "SUCCESS"));
        } catch (Exception e) {
            kafkaTemplate.send(cartsEventTopic, new CartCreateFailedEvent(command.accountCode(), "FAILURE"));
        }
    }
}
```
🧩 11. 이벤트 정의 (core/events)
```
public record CartCreatedEvent(String accountCode, String status) {}
public record CartCreateFailedEvent(String accountCode, String reason) {}
```
🔁 12. Saga 후속 처리 (Account-Service)
```
@KafkaHandler
public void handle(@Payload CartCreatedEvent event) {
    // 예치금 생성 명령 발행
}

@KafkaHandler
public void handle(@Payload CartCreateFailedEvent event) {
    // 사가 롤백 or 실패 알림 처리
}
```
🧩 13. 정리

전체 흐름

회원가입 성공 → AccountCreatedEvent 발행
→ Saga(AccountSaga)가 수신 → CreateCartCommand 발행
→ Demo-Service(CartHandler)가 수신 → CartCreatedEvent 발행
→ Saga가 수신 → DepositCommand 발행 (예치금 생성 단계)
→ ...


특징

서비스 간 직접 호출 없음

Kafka를 통한 느슨한 결합

사가가 상태를 조정하며 트랜잭션 완성

실패 이벤트 발행으로 롤백 가능

--
### 추가 고려 사항 실무 수준의 안정화 필요
좋다. 네 필기는 전체적으로 **Spring Cloud + Kafka 기반 사가(Choreography) 아키텍처의 핵심 흐름**을 잘 잡고 있다.
다만, 실무 수준으로 안정화하려면 아래 6개 정도를 추가하면 완성도가 높아진다.

---

### 1. **Kafka Consumer 재시도·DLT(Dead Letter Topic) 설정**

실패 시 메시지를 잃지 않게 하기 위해.

```yaml
spring:
  kafka:
    listener:
      ack-mode: record
      concurrency: 3
      retry:
        max-attempts: 3
      error-handler: seek-to-current
    template:
      default-topic: dead-letter-topic
```

또는 코드로 설정:

```java
@Bean
public DeadLetterPublishingRecoverer recoverer(KafkaTemplate<Object, Object> template) {
    return new DeadLetterPublishingRecoverer(template);
}

@Bean
public DefaultErrorHandler errorHandler(DeadLetterPublishingRecoverer recoverer) {
    return new DefaultErrorHandler(recoverer, new FixedBackOff(1000L, 3L));
}
```

> 실패 이벤트는 그냥 catch로 잡는 대신, DLT에 메시지를 보내두면 추적 및 재처리 가능.

---

### 2. **Kafka Listener 컨슈머 그룹 명시화**

`@KafkaListener`에 `groupId` 명시하면 토픽별 병렬 처리 관리가 명확해진다.

```java
@KafkaListener(topics = "${accounts.events.topic.name}", groupId = "account-saga")
```

---

### 3. **이벤트 Key 지정 (파티셔닝 보장)**

`kafkaTemplate.send(topic, key, payload)`로 보내야
같은 `accountCode`의 이벤트가 항상 동일 파티션에 들어감 → 순서 보장.

---

### 4. **코어 모듈 이벤트/커맨드 버전 관리**

`record AccountCreatedEventV1` 처럼 버전을 붙여두면
프로토콜 변경 시 서비스 간 충돌 방지.

---

### 5. **토픽 자동 생성 방지 → 인프라 초기화 스크립트 작성**

`allow.auto.create.topics=false` 설정했으므로
`infra/init-kafka-topics.sh` 같이 미리 토픽 생성 스크립트를 두는 게 좋다.

```bash
docker exec -it kafka-1 bash -c "/opt/kafka/bin/kafka-topics.sh \
  --create --topic accounts-events --bootstrap-server localhost:9092 \
  --partitions 3 --replication-factor 3"
```

---

### 6. **사가 상태 추적 테이블(optional)**

순수 코레오그래피는 이벤트 기반이라 상태 추적이 어렵다.
`saga_state` 테이블을 도입해 로그 남기면 디버깅이 쉬워진다.

```java
@Entity
public class SagaState {
  @Id String sagaId;
  String currentStep;
  String status; // PENDING, SUCCESS, FAILED
  LocalDateTime updatedAt;
}
```

---

요약:

| 영역               | 추가 내용            | 목적     |
| ---------------- | ---------------- | ------ |
| Kafka 재시도 & DLT  | 실패 복구            | 안정성    |
| Listener groupId | 컨슈머 병렬 처리 제어     | 명확성    |
| 이벤트 Key          | 파티셔닝 순서 보장       | 일관성    |
| 이벤트 버전           | 서비스 간 프로토콜 충돌 방지 | 확장성    |
| 초기화 스크립트         | 토픽 자동생성 방지 대응    | 인프라 관리 |
| 사가 상태 저장         | 분산 트랜잭션 추적       | 관측성    |

---
