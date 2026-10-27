---
title: "Облачные платформы: AWS, GCP, Azure, Kubernetes"
chapter: 4
difficulty: advanced
category: cloud
tags: [cloud, aws, gcp, azure, kubernetes, iam, imds, misconfiguration]
prerequisites:
  - "Web Security: инъекции, XSS и всё, что между ними"
  - "Сетевая безопасность: разведка, сервисы, сегментация"
related_payloads:
  - "payloads/cloud/aws-imdsv1-role-credentials.md"
  - "payloads/cloud/aws-s3-bucket-enum.md"
  - "payloads/cloud/gcp-metadata-token.md"
  - "payloads/cloud/azure-imds-managed-identity.md"
  - "payloads/cloud/kubernetes-anonymous-api.md"
  - "payloads/cloud/kubernetes-pod-sa-token.md"
  - "payloads/cloud/docker-socket-escape.md"
  - "payloads/web/ssrf/cloud-metadata-169254.md"
lab: null
---

# Облачные платформы: AWS, GCP, Azure, Kubernetes

В облаке почти не бывает «уязвимостей в коде платформы». Инциденты происходят из-за
**конфигурации**: публичный бакет, роль с `*:*`, IMDSv1 на инстансе, сервисный
аккаунт с `roles/editor`, открытый kubelet, `docker.sock` в CI-раннере.
Поэтому аудит облака — это аудит идентичностей и политик, а не сканирование портов.

## Общая модель: идентичность → роль → ресурс

```
┌──────────────┐   assume/attach   ┌──────────────┐   allows/denies   ┌──────────────┐
│ PRINCIPAL    │ ────────────────► │  ROLE /      │ ────────────────► │  RESOURCE +  │
│ user, SA,    │                   │  POLICY      │                   │  ACTION      │
│ instance,    │                   │ (JSON-документ)                  │ (s3:GetObject│
│ pod SA       │                   └──────────────┘                   │  ec2:Run...) │
└──────────────┘                                                      └──────────────┘
```

Три вопроса, на которые должен отвечать любой аудит:

1. **Кто** может получить эти права (включая временные токены из метаданных)?
2. **Что** эти права разрешают (есть ли `*` в action или resource)?
3. **Где** это можно использовать (из интернета? из другого аккаунта? из пода?)

## AWS

### Метаданные инстанса — главная точка входа

IMDSv1 не требует аутентификации, поэтому любой SSRF из приложения на EC2
превращается в утечку временных ключей роли инстанса.

```bash
# IMDSv1 — просто GET
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2 — сначала токен через PUT с ограниченным TTL
TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Проверка конфигурации изнутри аккаунта:

```bash
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{id:InstanceId,imds:MetadataOptions.HttpTokens,hop:MetadataOptions.HttpPutResponseHopLimit}'
```

Ожидаемое значение: `HttpTokens=required`, `HttpPutResponseHopLimit=1`.

### S3: три независимых способа стать публичным

| Механизм | Как проверить |
|----------|---------------|
| `BlockPublicAccess` выключен | `aws s3api get-public-access-block --bucket <name>` |
| Bucket policy с `Principal: "*"` | `aws s3api get-bucket-policy --bucket <name>` |
| ACL `AllUsers` / `AuthenticatedUsers` | `aws s3api get-bucket-acl --bucket <name>` |

```bash
# внешний доступ без учётных данных
aws s3 ls s3://target-bucket --no-sign-request
curl "https://target-bucket.s3.amazonaws.com/?list-type=2&max-keys=20"
```

Особое внимание — бакетам с Terraform state: внутри лежат секреты в открытом виде.

### IAM-эскалация: типовые опасные права

| Право | Почему даёт эскалацию |
|-------|----------------------|
| `iam:CreatePolicyVersion` | Новая версия политики с `*:*` и `SetAsDefault` |
| `iam:AttachRolePolicy` / `AttachUserPolicy` | Присоединить AdministratorAccess |
| `iam:PutRolePolicy` / `PutUserPolicy` | Вписать себе инлайн-политику |
| `iam:PassRole` + `lambda:CreateFunction` | Передать роль в функцию и выполнить её |
| `iam:PassRole` + `ec2:RunInstances` | Инстанс с привилегированной ролью + user-data |
| `lambda:UpdateFunctionCode` | Подменить код существующей функции с нужной ролью |
| `sts:AssumeRole` на широкий набор ролей | Горизонтальное движение по ролям |
| `s3:GetObject` на бакет с state/секретами | Ключи ко всему остальному |
| `ssm:StartSession` / `ssm:SendCommand` | Доступ к инстансам без SSH-ключей |
| `ecr:GetAuthorizationToken` + pull | Доступ к образам с секретами внутри |

```bash
# что я могу
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name <role>
# автоматизированный поиск путей эскалации
prowler aws --checks iam_role_allow_everyone,iam_policy_allows_privilege_escalation
```

### Чек-лист AWS

- [ ] IMDSv2 обязателен, hop limit = 1 (все launch-templates и AMI).
- [ ] `BlockPublicAccess` включён на уровне **аккаунта** и SCP запрещает его выключать.
- [ ] Нет политик с `Action: "*"` или `Resource: "*"` вне break-glass-ролей.
- [ ] Break-glass-роли под MFA + алертом на использование.
- [ ] Ключи доступа (`aws_access_key_id`) не старше 90 дней, лучше — отсутствуют вообще.
- [ ] CloudTrail включён во всех регионах + S3 Data Events для критичных бакетов.
- [ ] Логи CloudTrail защищены (Object Lock, отдельный аккаунт).
- [ ] Egress-ограничения: VPC endpoints вместо открытого интернета.
- [ ] Root-аккаунт: MFA, никаких ключей, не используется в операциях.
- [ ] SCP на уровне организации: запрет отключать защитные сервисы (GuardDuty, CloudTrail).

## GCP

### Metadata и сервисные аккаунты

```bash
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/?recursive=true"
```

Заголовок `Metadata-Flavor: Google` останавливает «бытовой» SSRF из браузера,
но не спасает от SSRF в серверном коде, LFI и RCE.

Типовые ошибки:

* `default` compute-сервисный аккаунт с `roles/editor` на проекте (наследие старых
  проектов) — фактически полный доступ к проекту;
* атрибуты проекта с `ssh-keys` — ключи, дающие вход на все ВМ;
* `identity?audience=...` — получение ID-токена для обхода IAP и доступа к Cloud Run;
* ключи сервисных аккаунтов, скачанные в JSON и лежащие в репозитории/бакете.

### Права, дающие эскалацию

| Право | Эффект |
|-------|--------|
| `resourcemanager.projects.setIamPolicy` | Выдать себе любую роль |
| `iam.serviceAccounts.getAccessToken` | Токен чужого сервисного аккаунта |
| `iam.serviceAccountKeys.create` | Создать постоянный ключ чужого SA |
| `compute.instances.setMetadata` | Инжект SSH-ключа или startup-script |
| `compute.instances.setServiceAccount` | Сменить SA работающей ВМ |
| `run.services.setIamPolicy` / `cloudfunctions.functions.update` | Доступ к workload'ам с привилегиями |
| `storage.objects.get` на бакетах с ключами/terraform.tfstate | Ключи ко всему |
| `container.clusters.get` + `roles/container.admin` | kubeconfig и доступ к кластеру |

```bash
gcloud projects get-iam-policy <project> --flatten="bindings[].members" \
  --format="table(bindings.role,bindings.members)"
# поиск сервисных аккаунтов с избыточными правами
gcloud iam service-accounts list
```

## Azure

### IMDS и managed identity

```bash
curl -H "Metadata: true" \
 "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

Полученный токен ARM позволяет перечислить подписки, группы ресурсов, хранилища
и Key Vault. Типовые находки: connection strings в настройках App Service,
`appsettings.json` в репозитории, ключи Storage Account в переменной окружения.

### Права, дающие эскалацию

| Роль / право | Эффект |
|--------------|--------|
| `Owner` / `Contributor` на подписке | Полный контроль, включая назначение ролей |
| `User Access Administrator` | Назначать роли — значит выдавать себе Owner |
| `Key Vault Secrets Officer` | Читать все секреты |
| `Automation Contributor` + Runbook | Выполнение кода с учёткой Automation (часто выше) |
| `Virtual Machine Contributor` | Доступ к секретам через VM extension / serial console |
| `AcrPull` + `AcrPush` | Подмена образа, который запускается с привилегированной identity |

```bash
az role assignment list --all -o table
az keyvault list -o table
az vm identity show -g <rg> -n <vm>
```

## Kubernetes и контейнеры

### Точки входа снаружи

| Точка | Как проверяется | Риск |
|-------|-----------------|------|
| API server 6443 | `curl -k https://<api>:6443/api/v1/namespaces` | Анонимный доступ, слабый RBAC |
| kubelet 10250 | `curl -k https://<node>:10250/pods` | Выполнение команд в подах |
| etcd 2379 | `etcdctl --endpoints=... get / --prefix --keys-only` | Все секреты кластера |
| Dashboard 8001/30228 | веб-интерфейс со skip-login | Полный доступ |
| Docker API 2375 | `curl http://<host>:2375/containers/json` | Root на хосте |
| Ingress/NodePort | открытые сервисы наружу | Приложение без NetworkPolicy |

### Изнутри пода

```bash
# токен сервисного аккаунта
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# что мне разрешено
kubectl auth can-i --list --token "$TOKEN" -n "$NS"
kubectl auth can-i get secrets --token "$TOKEN" -n "$NS"
kubectl auth can-i create pods/exec --token "$TOKEN" -n "$NS"
```

Опасные возможности SA:

* `get/list secrets` — чужие креды, docker-registry keys, TLS-ключи;
* `create pods/exec` — выполнение команд в других подах;
* `create pods` с `hostPath: /`, `hostPID`, `privileged` — выход на узел;
* `create clusterrolebindings` — cluster-admin;
* `patch/updatedaemonsets` — код на всех узлах кластера.

### Выход из контейнера

| Условие | Путь наружу |
|---------|-------------|
| `/var/run/docker.sock` смонтирован | Создать контейнер с `-v /:/host` и `chroot /host` |
| `--privileged` или `CAP_SYS_ADMIN` | cgroup release_agent, монтирование ФС хоста |
| `hostPath: /` | Чтение/запись корня хоста (в т.ч. `authorized_keys`) |
| `hostPID` + `CAP_SYS_PTRACE` | Чтение памяти процессов хоста |
| `hostNetwork` | Доступ к локальным сервисам узла (kubelet, etcd, metadata) |
| ядро < 5.x + уязвимости (runc, DirtyPipe) | Эксплойт контейнер-рантайма |

Проверка изнутри:

```bash
capsh --print                       # какие capabilities выданы
grep Cap /proc/self/status          # CapEff != 00000000a80425fb -> есть лишнее
mount | egrep 'docker|host|proc'    # подозрительные монтирования
ls -l /var/run/docker.sock          # сокет в контейнере = root на хосте
```

## Общий чек-лист облачного аудита

- [ ] **Идентичности**: нет постоянных ключей; workload identity / роли инстансов /
      managed identity; MFA для людей; SSO вместо локальных учётных записей.
- [ ] **Права**: нет `*` в action/resource; привилегированные роли под MFA/Just-In-Time;
      ежеквартальный access review.
- [ ] **Метаданные**: IMDSv2 / `Metadata-Flavor` / hop limit; egress-блокировка
      169.254.169.254 там, где она не нужна.
- [ ] **Хранилища**: публичность запрещена политикой организации; шифрование;
      версионирование; мониторинг аномальных `GetObject`.
- [ ] **Сеть**: приватные подсети, NAT/VPCE, Security Groups без `0.0.0.0/0` на
      админ-порты; приватные эндпоинты для данных.
- [ ] **Контейнеры**: не privileged, без `hostPath: /`, без docker.sock;
      PSS `restricted`; NetworkPolicy deny-all; read-only rootfs; образы из доверенного
      реестра со сканированием.
- [ ] **Логи и мониторинг**: аудит-логи включены и защищены; алерты на
      изменение политик, создание ключей, публичный доступ, `AssumeRole` извне.
- [ ] **IaC**: terraform state зашифрован и не публичен; `tfsec`/`checkov`/`trivy`
      в CI; секреты не в коде.

## Практика

Для облачной части используются локальные стенды (minikube/kind + локальный
реестр) и **никогда** — боевые аккаунты без письменного разрешения:

```bash
# локальный k8s для отработки RBAC и container escape
kind create cluster --name hackbook
kubectl create ns vulnerable
kubectl apply -f labs/cloud-labs/rbac-vulnerable.yaml   # SA с избыточными правами

# проверка конфигурации кластера
kubectl auth can-i --list --as=system:serviceaccount:vulnerable:app-sa
kube-bench run --targets node,controlplane
```

Задания:

1. В локальном kind-кластере найдите SA с правом `get secrets` и извлеките секрет
   другого namespace. Объясните, какой RBAC-объект это разрешил.
2. Создайте под с `hostPath: /` и прочитайте `/etc/hostname` узла. Затем напишите
   Kyverno-политику, которая запрещает такие поды.
3. Смонтируйте `docker.sock` в тестовый контейнер, выйдите на хост, и опишите три
   способа добиться того же результата без сокета.
4. Для облачной части (учебный аккаунт): включите IMDSv2, снимите `roles/editor`
   с default SA, создайте отдельный SA с минимальной ролью и подтвердите, что
   метаданные больше не дают лишнего.
5. Напишите скрипт-чекер, который выводит список ролей с `*` в action или resource
   и запускается в CI на этапе `terraform plan`.
