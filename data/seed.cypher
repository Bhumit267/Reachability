// ==========================================
// SEED DATA FOR CVE COMMANDER
// Track 01 & 02 Graph Context & Memory
// ==========================================

// --- 1. SERVICES (10 Services) ---
MERGE (s1:Service {id: 'svc-payments-api', name: 'payments-api', tier: 'Tier-1', critical: true, language: 'python'});
MERGE (s2:Service {id: 'svc-auth-service', name: 'auth-service', tier: 'Tier-1', critical: true, language: 'golang'});
MERGE (s3:Service {id: 'svc-billing-worker', name: 'billing-worker', tier: 'Tier-1', critical: true, language: 'python'});
MERGE (s4:Service {id: 'svc-user-dashboard', name: 'user-dashboard', tier: 'Tier-2', critical: false, language: 'typescript'});
MERGE (s5:Service {id: 'svc-notification-svc', name: 'notification-svc', tier: 'Tier-2', critical: false, language: 'python'});
MERGE (s6:Service {id: 'svc-order-processor', name: 'order-processor', tier: 'Tier-1', critical: true, language: 'java'});
MERGE (s7:Service {id: 'svc-inventory-svc', name: 'inventory-svc', tier: 'Tier-2', critical: false, language: 'golang'});
MERGE (s8:Service {id: 'svc-analytics-pipeline', name: 'analytics-pipeline', tier: 'Tier-3', critical: false, language: 'python'});
MERGE (s9:Service {id: 'svc-search-api', name: 'search-api', tier: 'Tier-2', critical: false, language: 'rust'});
MERGE (s10:Service {id: 'svc-shipping-gateway', name: 'shipping-gateway', tier: 'Tier-2', critical: false, language: 'python'});

// --- 2. CROWN JEWELS (5 Crown Jewels) ---
MERGE (cj1:CrownJewel {id: 'cj-customer-pii', name: 'CustomerPIIStore', classification: 'RESTRICTED', description: 'Customer PII, SSNs, and identity verification records'});
MERGE (cj2:CrownJewel {id: 'cj-payment-ledger', name: 'PaymentLedger', classification: 'RESTRICTED', description: 'Primary immutable financial ledger and PCI payment vault'});
MERGE (cj3:CrownJewel {id: 'cj-auth-secrets', name: 'AuthSecrets', classification: 'TOP-SECRET', description: 'Master KMS keys, signing credentials, and OAuth root secrets'});
MERGE (cj4:CrownJewel {id: 'cj-audit-log', name: 'FinancialAuditLog', classification: 'CONFIDENTIAL', description: 'WORM financial audit and compliance logs'});
MERGE (cj5:CrownJewel {id: 'cj-customer-vault', name: 'PrimaryCustomerVault', classification: 'RESTRICTED', description: 'PCI-DSS tokenized cardholder data store'});

// --- 3. ASSETS (15 Assets: servers, dbs, queues) ---
MERGE (a1:Asset {id: 'asset-payments-prod-01', name: 'k8s-node-payments-prod-01', type: 'server', ip: '10.0.12.44', zone: 'us-east-1a'});
MERGE (a2:Asset {id: 'asset-payments-db-01', name: 'rds-pg-payments-master', type: 'database', ip: '10.0.12.180', zone: 'us-east-1a'});
MERGE (a3:Asset {id: 'asset-auth-prod-01', name: 'k8s-node-auth-prod-01', type: 'server', ip: '10.0.10.15', zone: 'us-east-1b'});
MERGE (a4:Asset {id: 'asset-billing-worker-01', name: 'ec2-billing-worker-01', type: 'server', ip: '10.0.14.22', zone: 'us-east-1c'});
MERGE (a5:Asset {id: 'asset-user-dash-01', name: 'k8s-node-dashboard-01', type: 'server', ip: '10.0.20.10', zone: 'us-east-1a'});
MERGE (a6:Asset {id: 'asset-notif-queue-01', name: 'rabbitmq-notif-cluster-01', type: 'queue', ip: '10.0.30.5', zone: 'us-east-1b'});
MERGE (a7:Asset {id: 'asset-order-proc-01', name: 'k8s-node-orders-01', type: 'server', ip: '10.0.12.99', zone: 'us-east-1a'});
MERGE (a8:Asset {id: 'asset-inventory-db-01', name: 'aurora-pg-inventory-01', type: 'database', ip: '10.0.16.50', zone: 'us-east-1b'});
MERGE (a9:Asset {id: 'asset-analytics-node-01', name: 'clickhouse-analytics-01', type: 'database', ip: '10.0.40.11', zone: 'us-east-1c'});
MERGE (a10:Asset {id: 'asset-search-cluster-01', name: 'opensearch-search-01', type: 'database', ip: '10.0.50.21', zone: 'us-east-1a'});
MERGE (a11:Asset {id: 'asset-shipping-edge-01', name: 'kong-shipping-edge-01', type: 'server', ip: '10.0.60.100', zone: 'us-east-1b'});
MERGE (a12:Asset {id: 'asset-redis-cache-01', name: 'redis-payments-cache-01', type: 'database', ip: '10.0.12.210', zone: 'us-east-1a'});
MERGE (a13:Asset {id: 'asset-kafka-cluster-01', name: 'kafka-events-broker-01', type: 'queue', ip: '10.0.70.12', zone: 'us-east-1c'});
MERGE (a14:Asset {id: 'asset-vault-node-01', name: 'hashicorp-vault-prod-01', type: 'server', ip: '10.0.1.5', zone: 'us-east-1a'});
MERGE (a15:Asset {id: 'asset-audit-collector-01', name: 'fluentbit-audit-prod-01', type: 'server', ip: '10.0.2.14', zone: 'us-east-1b'});

// --- 4. VULNERABILITIES (3-4 per asset, CRITICAL CVE on payments-api asset) ---
MERGE (v_crit:Vulnerability {id: 'CVE-2024-3094', cve_id: 'CVE-2024-3094', title: 'XZ Utils Backdoor Remote Code Execution', severity: 'CRITICAL', cvss: 10.0, published: '2024-03-29'});
MERGE (v2:Vulnerability {id: 'CVE-2023-44487', cve_id: 'CVE-2023-44487', title: 'HTTP/2 Rapid Reset Attack', severity: 'HIGH', cvss: 7.5, published: '2023-10-10'});
MERGE (v3:Vulnerability {id: 'CVE-2024-21626', cve_id: 'CVE-2024-21626', title: 'runc Container Breakout via File Descriptor Leak', severity: 'HIGH', cvss: 8.6, published: '2024-01-31'});
MERGE (v4:Vulnerability {id: 'CVE-2023-48795', cve_id: 'CVE-2023-48795', title: 'Terrapin SSH Protocol Prefix Truncation', severity: 'MEDIUM', cvss: 5.9, published: '2023-12-18'});
MERGE (v5:Vulnerability {id: 'CVE-2024-6387', cve_id: 'CVE-2024-6387', title: 'regreSSHion OpenSSH Pre-auth Remote Code Execution', severity: 'HIGH', cvss: 8.1, published: '2024-07-01'});
MERGE (v6:Vulnerability {id: 'CVE-2023-38545', cve_id: 'CVE-2023-38545', title: 'cURL SOCKS5 Heap Buffer Overflow', severity: 'HIGH', cvss: 7.8, published: '2023-10-11'});
MERGE (v7:Vulnerability {id: 'CVE-2023-4911', cve_id: 'CVE-2023-4911', title: 'Looney Tunables glibc Privilege Escalation', severity: 'HIGH', cvss: 7.8, published: '2023-10-03'});
MERGE (v8:Vulnerability {id: 'CVE-2024-24576', cve_id: 'CVE-2024-24576', title: 'Rust Standard Library Command Injection on Windows', severity: 'HIGH', cvss: 8.5, published: '2024-04-09'});
MERGE (v9:Vulnerability {id: 'CVE-2023-5868', cve_id: 'CVE-2023-5868', title: 'PostgreSQL Buffer Overflow in Aggregate Functions', severity: 'MEDIUM', cvss: 6.5, published: '2023-11-09'});
MERGE (v10:Vulnerability {id: 'CVE-2024-1597', cve_id: 'CVE-2024-1597', title: 'PostgreSQL JDBC Driver SQL Injection', severity: 'HIGH', cvss: 7.5, published: '2024-02-15'});
MERGE (v11:Vulnerability {id: 'CVE-2023-46118', cve_id: 'CVE-2023-46118', title: 'RabbitMQ Web Management DoS via Large Payloads', severity: 'MEDIUM', cvss: 6.5, published: '2023-10-25'});
MERGE (v12:Vulnerability {id: 'CVE-2023-45145', cve_id: 'CVE-2023-45145', title: 'Redis Denial of Service via Malicious Command Parsing', severity: 'MEDIUM', cvss: 5.3, published: '2023-10-18'});
MERGE (v13:Vulnerability {id: 'CVE-2023-34455', cve_id: 'CVE-2023-34455', title: 'Kafka Clients Memory Leak in Snappy Decompression', severity: 'MEDIUM', cvss: 5.5, published: '2023-06-08'});

// Link Assets to Vulnerabilities (3-4 vulns each)
MATCH (a:Asset {id: 'asset-payments-prod-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2024-3094', 'CVE-2023-44487', 'CVE-2024-21626', 'CVE-2023-48795'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-payments-db-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-5868', 'CVE-2024-1597', 'CVE-2023-48795'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-auth-prod-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2024-6387', 'CVE-2023-38545', 'CVE-2024-24576'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-billing-worker-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-4911', 'CVE-2024-21626', 'CVE-2023-48795'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-user-dash-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-44487', 'CVE-2024-24576', 'CVE-2023-38545'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-notif-queue-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-46118', 'CVE-2023-48795', 'CVE-2024-1597'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-order-proc-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2024-21626', 'CVE-2023-4911', 'CVE-2024-6387'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-inventory-db-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-5868', 'CVE-2024-1597', 'CVE-2023-48795'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-analytics-node-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-44487', 'CVE-2023-48795', 'CVE-2024-24576'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-search-cluster-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-46118', 'CVE-2023-38545', 'CVE-2024-6387'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-shipping-edge-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-44487', 'CVE-2024-21626', 'CVE-2023-4911'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-redis-cache-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-45145', 'CVE-2023-48795', 'CVE-2024-1597'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-kafka-cluster-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-34455', 'CVE-2024-21626', 'CVE-2023-44487'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-vault-node-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-5868', 'CVE-2024-6387', 'CVE-2023-4911'] MERGE (a)-[:HAS_VULN]->(v);
MATCH (a:Asset {id: 'asset-audit-collector-01'}), (v:Vulnerability) WHERE v.id IN ['CVE-2023-38545', 'CVE-2023-48795', 'CVE-2024-24576'] MERGE (a)-[:HAS_VULN]->(v);

// --- 5. SERVICE -> ASSET RUNS_ON MAPPINGS ---
MATCH (s:Service {id: 'svc-payments-api'}), (a:Asset {id: 'asset-payments-prod-01'}) MERGE (s)-[:RUNS_ON]->(a);
MATCH (s:Service {id: 'svc-payments-api'}), (a:Asset {id: 'asset-payments-db-01'}) MERGE (s)-[:RUNS_ON]->(a);
MATCH (s:Service {id: 'svc-payments-api'}), (a:Asset {id: 'asset-redis-cache-01'}) MERGE (s)-[:RUNS_ON]->(a);
MATCH (s:Service {id: 'svc-auth-service'}), (a:Asset {id: 'asset-auth-prod-01'}) MERGE (s)-[:RUNS_ON]->(a);
MATCH (s:Service {id: 'svc-billing-worker'}), (a:Asset {id: 'asset-billing-worker-01'}) MERGE (s)-[:RUNS_ON]->(a);
MATCH (s:Service {id: 'svc-user-dashboard'}), (a:Asset {id: 'asset-user-dash-01'}) MERGE (s)-[:RUNS_ON]->(a);
MATCH (s:Service {id: 'svc-notification-svc'}), (a:Asset {id: 'asset-notif-queue-01'}) MERGE (s)-[:RUNS_ON]->(a);
MATCH (s:Service {id: 'svc-order-processor'}), (a:Asset {id: 'asset-order-proc-01'}) MERGE (s)-[:RUNS_ON]->(a);
MATCH (s:Service {id: 'svc-inventory-svc'}), (a:Asset {id: 'asset-inventory-db-01'}) MERGE (s)-[:RUNS_ON]->(a);
MATCH (s:Service {id: 'svc-analytics-pipeline'}), (a:Asset {id: 'asset-analytics-node-01'}) MERGE (s)-[:RUNS_ON]->(a);
MATCH (s:Service {id: 'svc-search-api'}), (a:Asset {id: 'asset-search-cluster-01'}) MERGE (s)-[:RUNS_ON]->(a);
MATCH (s:Service {id: 'svc-shipping-gateway'}), (a:Asset {id: 'asset-shipping-edge-01'}) MERGE (s)-[:RUNS_ON]->(a);

// --- 6. ASSET -> CROWN JEWEL REACHABILITY ---
MATCH (a:Asset {id: 'asset-payments-prod-01'}), (cj:CrownJewel {id: 'cj-payment-ledger'}) MERGE (a)-[:REACHES {protocol: 'mTLS', port: 8443, direct: true}]->(cj);
MATCH (a:Asset {id: 'asset-payments-prod-01'}), (cj:CrownJewel {id: 'cj-customer-pii'}) MERGE (a)-[:REACHES {protocol: 'PostgresSSL', port: 5432, direct: true}]->(cj);
MATCH (a:Asset {id: 'asset-auth-prod-01'}), (cj:CrownJewel {id: 'cj-auth-secrets'}) MERGE (a)-[:REACHES {protocol: 'gRPC', port: 9000, direct: true}]->(cj);
MATCH (a:Asset {id: 'asset-billing-worker-01'}), (cj:CrownJewel {id: 'cj-payment-ledger'}) MERGE (a)-[:REACHES {protocol: 'mTLS', port: 8443, direct: true}]->(cj);
MATCH (a:Asset {id: 'asset-vault-node-01'}), (cj:CrownJewel {id: 'cj-customer-vault'}) MERGE (a)-[:REACHES {protocol: 'HTTPS', port: 8200, direct: true}]->(cj);
MATCH (a:Asset {id: 'asset-audit-collector-01'}), (cj:CrownJewel {id: 'cj-audit-log'}) MERGE (a)-[:REACHES {protocol: 'TCP', port: 24224, direct: true}]->(cj);

// --- 7. OWNERS & ON-CALL (5 Owners, 5 OnCall) ---
MERGE (o1:Owner {id: 'owner-alice', name: 'Alice Smith', team: 'Payments Core Team', email: 'alice.smith@fintech.io', slack: '@alice'});
MERGE (o2:Owner {id: 'owner-bob', name: 'Bob Jones', team: 'Auth & Identity Team', email: 'bob.jones@fintech.io', slack: '@bob'});
MERGE (o3:Owner {id: 'owner-carol', name: 'Carol Danvers', team: 'Billing Operations', email: 'carol.danvers@fintech.io', slack: '@carol'});
MERGE (o4:Owner {id: 'owner-david', name: 'David Kim', team: 'Web Experience & Dashboards', email: 'david.kim@fintech.io', slack: '@david'});
MERGE (o5:Owner {id: 'owner-eve', name: 'Eve Jackson', team: 'Infrastructure Platform & SRE', email: 'eve.jackson@fintech.io', slack: '@eve'});

MERGE (oc1:OnCall {id: 'oncall-payments', name: 'Payments On-Call Primary', schedule: '2024-W42-Primary', phone: '+1-555-0101', pagerduty_id: 'PD-PAYMENTS-01', active: true});
MERGE (oc2:OnCall {id: 'oncall-auth', name: 'Auth On-Call Primary', schedule: '2024-W42-Primary', phone: '+1-555-0102', pagerduty_id: 'PD-AUTH-01', active: true});
MERGE (oc3:OnCall {id: 'oncall-billing', name: 'Billing On-Call Primary', schedule: '2024-W42-Primary', phone: '+1-555-0103', pagerduty_id: 'PD-BILLING-01', active: true});
MERGE (oc4:OnCall {id: 'oncall-frontend', name: 'Frontend On-Call Primary', schedule: '2024-W42-Primary', phone: '+1-555-0104', pagerduty_id: 'PD-FRONTEND-01', active: true});
MERGE (oc5:OnCall {id: 'oncall-infra', name: 'Infra SRE On-Call Primary', schedule: '2024-W42-Primary', phone: '+1-555-0105', pagerduty_id: 'PD-INFRA-01', active: true});

MATCH (o:Owner {id: 'owner-alice'}), (oc:OnCall {id: 'oncall-payments'}) MERGE (o)-[:ON_CALL]->(oc);
MATCH (o:Owner {id: 'owner-bob'}), (oc:OnCall {id: 'oncall-auth'}) MERGE (o)-[:ON_CALL]->(oc);
MATCH (o:Owner {id: 'owner-carol'}), (oc:OnCall {id: 'oncall-billing'}) MERGE (o)-[:ON_CALL]->(oc);
MATCH (o:Owner {id: 'owner-david'}), (oc:OnCall {id: 'oncall-frontend'}) MERGE (o)-[:ON_CALL]->(oc);
MATCH (o:Owner {id: 'owner-eve'}), (oc:OnCall {id: 'oncall-infra'}) MERGE (o)-[:ON_CALL]->(oc);

// Map Services to Owners
MATCH (s:Service {id: 'svc-payments-api'}), (o:Owner {id: 'owner-alice'}) MERGE (s)-[:OWNED_BY]->(o);
MATCH (s:Service {id: 'svc-order-processor'}), (o:Owner {id: 'owner-alice'}) MERGE (s)-[:OWNED_BY]->(o);
MATCH (s:Service {id: 'svc-auth-service'}), (o:Owner {id: 'owner-bob'}) MERGE (s)-[:OWNED_BY]->(o);
MATCH (s:Service {id: 'svc-billing-worker'}), (o:Owner {id: 'owner-carol'}) MERGE (s)-[:OWNED_BY]->(o);
MATCH (s:Service {id: 'svc-inventory-svc'}), (o:Owner {id: 'owner-carol'}) MERGE (s)-[:OWNED_BY]->(o);
MATCH (s:Service {id: 'svc-user-dashboard'}), (o:Owner {id: 'owner-david'}) MERGE (s)-[:OWNED_BY]->(o);
MATCH (s:Service {id: 'svc-notification-svc'}), (o:Owner {id: 'owner-david'}) MERGE (s)-[:OWNED_BY]->(o);
MATCH (s:Service {id: 'svc-analytics-pipeline'}), (o:Owner {id: 'owner-eve'}) MERGE (s)-[:OWNED_BY]->(o);
MATCH (s:Service {id: 'svc-search-api'}), (o:Owner {id: 'owner-eve'}) MERGE (s)-[:OWNED_BY]->(o);
MATCH (s:Service {id: 'svc-shipping-gateway'}), (o:Owner {id: 'owner-eve'}) MERGE (s)-[:OWNED_BY]->(o);

// --- 8. REPOS, FILES, FUNCTIONS (5 Repos, 3-6 Files, 2-4 Functions each) ---

// Repo 1: payments-api (MUST contain payment_handler.py with process_payment())
MERGE (r1:Repo {id: 'repo-payments-api', name: 'payments-api-service', url: 'https://github.com/fintech/payments-api', default_branch: 'main'});
MATCH (s:Service {id: 'svc-payments-api'}), (r:Repo {id: 'repo-payments-api'}) MERGE (s)-[:HAS_REPO]->(r);

MERGE (f1_1:File {id: 'file-payment-handler', path: 'src/payment_handler.py', repo_id: 'repo-payments-api'});
MERGE (f1_2:File {id: 'file-checkout-router', path: 'src/checkout_router.py', repo_id: 'repo-payments-api'});
MERGE (f1_3:File {id: 'file-gateway-client', path: 'src/gateway_client.py', repo_id: 'repo-payments-api'});
MERGE (f1_4:File {id: 'file-config-loader', path: 'src/config_loader.py', repo_id: 'repo-payments-api'});

MATCH (r:Repo {id: 'repo-payments-api'}), (f:File) WHERE f.id IN ['file-payment-handler', 'file-checkout-router', 'file-gateway-client', 'file-config-loader'] MERGE (r)-[:CONTAINS]->(f);

MERGE (fn1_1:Function {id: 'fn-process-payment', name: 'process_payment', signature: 'process_payment(amount: float, token: str) -> TransactionResult', file_id: 'file-payment-handler'});
MERGE (fn1_2:Function {id: 'fn-validate-card', name: 'validate_card', signature: 'validate_card(card_data: dict) -> bool', file_id: 'file-payment-handler'});
MERGE (fn1_3:Function {id: 'fn-refund-charge', name: 'refund_charge', signature: 'refund_charge(txn_id: str, amount: float) -> RefundResult', file_id: 'file-payment-handler'});
MATCH (f:File {id: 'file-payment-handler'}), (fn:Function) WHERE fn.id IN ['fn-process-payment', 'fn-validate-card', 'fn-refund-charge'] MERGE (f)-[:DEFINES]->(fn);

MERGE (fn1_4:Function {id: 'fn-route-checkout', name: 'route_checkout', signature: 'route_checkout(cart_id: str) -> RouteResponse', file_id: 'file-checkout-router'});
MERGE (fn1_5:Function {id: 'fn-apply-discount', name: 'apply_discount', signature: 'apply_discount(code: str) -> float', file_id: 'file-checkout-router'});
MATCH (f:File {id: 'file-checkout-router'}), (fn:Function) WHERE fn.id IN ['fn-route-checkout', 'fn-apply-discount'] MERGE (f)-[:DEFINES]->(fn);

MERGE (fn1_6:Function {id: 'fn-send-processor', name: 'send_to_processor', signature: 'send_to_processor(payload: bytes) -> bytes', file_id: 'file-gateway-client'});
MERGE (fn1_7:Function {id: 'fn-check-status', name: 'check_transaction_status', signature: 'check_transaction_status(txn_id: str) -> str', file_id: 'file-gateway-client'});
MATCH (f:File {id: 'file-gateway-client'}), (fn:Function) WHERE fn.id IN ['fn-send-processor', 'fn-check-status'] MERGE (f)-[:DEFINES]->(fn);

MERGE (fn1_8:Function {id: 'fn-load-creds', name: 'load_payment_creds', signature: 'load_payment_creds() -> dict', file_id: 'file-config-loader'});
MERGE (fn1_9:Function {id: 'fn-verify-keys', name: 'verify_keys', signature: 'verify_keys(keys: dict) -> bool', file_id: 'file-config-loader'});
MATCH (f:File {id: 'file-config-loader'}), (fn:Function) WHERE fn.id IN ['fn-load-creds', 'fn-verify-keys'] MERGE (f)-[:DEFINES]->(fn);

// Repo 2: auth-service
MERGE (r2:Repo {id: 'repo-auth-service', name: 'auth-service-core', url: 'https://github.com/fintech/auth-service', default_branch: 'main'});
MATCH (s:Service {id: 'svc-auth-service'}), (r:Repo {id: 'repo-auth-service'}) MERGE (s)-[:HAS_REPO]->(r);

MERGE (f2_1:File {id: 'file-jwt-manager', path: 'pkg/jwt_manager.go', repo_id: 'repo-auth-service'});
MERGE (f2_2:File {id: 'file-oauth-provider', path: 'pkg/oauth_provider.go', repo_id: 'repo-auth-service'});
MERGE (f2_3:File {id: 'file-session-store', path: 'pkg/session_store.go', repo_id: 'repo-auth-service'});
MATCH (r:Repo {id: 'repo-auth-service'}), (f:File) WHERE f.id IN ['file-jwt-manager', 'file-oauth-provider', 'file-session-store'] MERGE (r)-[:CONTAINS]->(f);

MERGE (fn2_1:Function {id: 'fn-issue-token', name: 'issue_token', signature: 'IssueToken(claims Claims) (string, error)', file_id: 'file-jwt-manager'});
MERGE (fn2_2:Function {id: 'fn-verify-signature', name: 'verify_signature', signature: 'VerifySignature(token string) bool', file_id: 'file-jwt-manager'});
MATCH (f:File {id: 'file-jwt-manager'}), (fn:Function) WHERE fn.id IN ['fn-issue-token', 'fn-verify-signature'] MERGE (f)-[:DEFINES]->(fn);

MERGE (fn2_3:Function {id: 'fn-authorize-user', name: 'authorize_user', signature: 'AuthorizeUser(code string) UserSession', file_id: 'file-oauth-provider'});
MERGE (fn2_4:Function {id: 'fn-exchange-code', name: 'exchange_code', signature: 'ExchangeCode(token string) bool', file_id: 'file-oauth-provider'});
MATCH (f:File {id: 'file-oauth-provider'}), (fn:Function) WHERE fn.id IN ['fn-authorize-user', 'fn-exchange-code'] MERGE (f)-[:DEFINES]->(fn);

MERGE (fn2_5:Function {id: 'fn-get-session', name: 'get_session', signature: 'GetSession(sid string) Session', file_id: 'file-session-store'});
MERGE (fn2_6:Function {id: 'fn-invalidate-session', name: 'invalidate_session', signature: 'InvalidateSession(sid string) error', file_id: 'file-session-store'});
MATCH (f:File {id: 'file-session-store'}), (fn:Function) WHERE fn.id IN ['fn-get-session', 'fn-invalidate-session'] MERGE (f)-[:DEFINES]->(fn);

// Repo 3: billing-worker
MERGE (r3:Repo {id: 'repo-billing-worker', name: 'billing-engine', url: 'https://github.com/fintech/billing-worker', default_branch: 'main'});
MATCH (s:Service {id: 'svc-billing-worker'}), (r:Repo {id: 'repo-billing-worker'}) MERGE (s)-[:HAS_REPO]->(r);

MERGE (f3_1:File {id: 'file-invoice-gen', path: 'src/invoice_gen.py', repo_id: 'repo-billing-worker'});
MERGE (f3_2:File {id: 'file-sub-engine', path: 'src/subscription_engine.py', repo_id: 'repo-billing-worker'});
MERGE (f3_3:File {id: 'file-tax-calc', path: 'src/tax_calculator.py', repo_id: 'repo-billing-worker'});
MATCH (r:Repo {id: 'repo-billing-worker'}), (f:File) WHERE f.id IN ['file-invoice-gen', 'file-sub-engine', 'file-tax-calc'] MERGE (r)-[:CONTAINS]->(f);

MERGE (fn3_1:Function {id: 'fn-generate-invoice', name: 'generate_invoice', signature: 'generate_invoice(account_id: str) -> Invoice', file_id: 'file-invoice-gen'});
MERGE (fn3_2:Function {id: 'fn-send-receipt', name: 'send_receipt', signature: 'send_receipt(inv_id: str) -> bool', file_id: 'file-invoice-gen'});
MATCH (f:File {id: 'file-invoice-gen'}), (fn:Function) WHERE fn.id IN ['fn-generate-invoice', 'fn-send-receipt'] MERGE (f)-[:DEFINES]->(fn);

MERGE (fn3_3:Function {id: 'fn-renew-sub', name: 'renew_subscription', signature: 'renew_subscription(sub_id: str) -> bool', file_id: 'file-sub-engine'});
MERGE (fn3_4:Function {id: 'fn-cancel-sub', name: 'cancel_subscription', signature: 'cancel_subscription(sub_id: str) -> bool', file_id: 'file-sub-engine'});
MATCH (f:File {id: 'file-sub-engine'}), (fn:Function) WHERE fn.id IN ['fn-renew-sub', 'fn-cancel-sub'] MERGE (f)-[:DEFINES]->(fn);

MERGE (fn3_5:Function {id: 'fn-calc-vat', name: 'calculate_vat', signature: 'calculate_vat(country: str, amt: float) -> float', file_id: 'file-tax-calc'});
MERGE (fn3_6:Function {id: 'fn-lookup-jurisdiction', name: 'lookup_jurisdiction', signature: 'lookup_jurisdiction(zip_code: str) -> str', file_id: 'file-tax-calc'});
MATCH (f:File {id: 'file-tax-calc'}), (fn:Function) WHERE fn.id IN ['fn-calc-vat', 'fn-lookup-jurisdiction'] MERGE (f)-[:DEFINES]->(fn);

// Repo 4: user-dashboard
MERGE (r4:Repo {id: 'repo-user-dashboard', name: 'user-portal-ui', url: 'https://github.com/fintech/user-dashboard', default_branch: 'main'});
MATCH (s:Service {id: 'svc-user-dashboard'}), (r:Repo {id: 'repo-user-dashboard'}) MERGE (s)-[:HAS_REPO]->(r);

MERGE (f4_1:File {id: 'file-user-controller', path: 'src/user_controller.ts', repo_id: 'repo-user-dashboard'});
MERGE (f4_2:File {id: 'file-profile-service', path: 'src/profile_service.ts', repo_id: 'repo-user-dashboard'});
MERGE (f4_3:File {id: 'file-settings-view', path: 'src/settings_view.tsx', repo_id: 'repo-user-dashboard'});
MATCH (r:Repo {id: 'repo-user-dashboard'}), (f:File) WHERE f.id IN ['file-user-controller', 'file-profile-service', 'file-settings-view'] MERGE (r)-[:CONTAINS]->(f);

MERGE (fn4_1:Function {id: 'fn-get-profile', name: 'get_profile', signature: 'getProfile(userId: string): Promise<User>', file_id: 'file-user-controller'});
MERGE (fn4_2:Function {id: 'fn-update-settings', name: 'update_settings', signature: 'updateSettings(cfg: UserConfig): void', file_id: 'file-user-controller'});
MATCH (f:File {id: 'file-user-controller'}), (fn:Function) WHERE fn.id IN ['fn-get-profile', 'fn-update-settings'] MERGE (f)-[:DEFINES]->(fn);

MERGE (fn4_3:Function {id: 'fn-fetch-avatar', name: 'fetch_avatar', signature: 'fetchAvatar(url: string): Blob', file_id: 'file-profile-service'});
MERGE (fn4_4:Function {id: 'fn-sync-prefs', name: 'sync_preferences', signature: 'syncPreferences(p: Prefs): boolean', file_id: 'file-profile-service'});
MATCH (f:File {id: 'file-profile-service'}), (fn:Function) WHERE fn.id IN ['fn-fetch-avatar', 'fn-sync-prefs'] MERGE (f)-[:DEFINES]->(fn);

MERGE (fn4_5:Function {id: 'fn-render-security', name: 'render_security_tab', signature: 'renderSecurityTab(): JSX.Element', file_id: 'file-settings-view'});
MERGE (fn4_6:Function {id: 'fn-export-user-data', name: 'export_user_data', signature: 'exportUserData(uid: string): JSON', file_id: 'file-settings-view'});
MATCH (f:File {id: 'file-settings-view'}), (fn:Function) WHERE fn.id IN ['fn-render-security', 'fn-export-user-data'] MERGE (f)-[:DEFINES]->(fn);

// Repo 5: notification-svc
MERGE (r5:Repo {id: 'repo-notification-svc', name: 'notification-dispatch', url: 'https://github.com/fintech/notification-svc', default_branch: 'main'});
MATCH (s:Service {id: 'svc-notification-svc'}), (r:Repo {id: 'repo-notification-svc'}) MERGE (s)-[:HAS_REPO]->(r);

MERGE (f5_1:File {id: 'file-email-sender', path: 'src/email_sender.py', repo_id: 'repo-notification-svc'});
MERGE (f5_2:File {id: 'file-slack-dispatcher', path: 'src/slack_dispatcher.py', repo_id: 'repo-notification-svc'});
MERGE (f5_3:File {id: 'file-sms-gateway', path: 'src/sms_gateway.py', repo_id: 'repo-notification-svc'});
MATCH (r:Repo {id: 'repo-notification-svc'}), (f:File) WHERE f.id IN ['file-email-sender', 'file-slack-dispatcher', 'file-sms-gateway'] MERGE (r)-[:CONTAINS]->(f);

MERGE (fn5_1:Function {id: 'fn-send-templated-email', name: 'send_templated_email', signature: 'send_templated_email(to: str, template: str) -> bool', file_id: 'file-email-sender'});
MERGE (fn5_2:Function {id: 'fn-verify-smtp', name: 'verify_smtp', signature: 'verify_smtp() -> bool', file_id: 'file-email-sender'});
MATCH (f:File {id: 'file-email-sender'}), (fn:Function) WHERE fn.id IN ['fn-send-templated-email', 'fn-verify-smtp'] MERGE (f)-[:DEFINES]->(fn);

MERGE (fn5_3:Function {id: 'fn-post-alert', name: 'post_incident_alert', signature: 'post_incident_alert(channel: str, msg: str) -> None', file_id: 'file-slack-dispatcher'});
MERGE (fn5_4:Function {id: 'fn-format-blocks', name: 'format_blocks', signature: 'format_blocks(payload: dict) -> list', file_id: 'file-slack-dispatcher'});
MATCH (f:File {id: 'file-slack-dispatcher'}), (fn:Function) WHERE fn.id IN ['fn-post-alert', 'fn-format-blocks'] MERGE (f)-[:DEFINES]->(fn);

MERGE (fn5_5:Function {id: 'fn-dispatch-sms', name: 'dispatch_sms', signature: 'dispatch_sms(phone: str, msg: str) -> bool', file_id: 'file-sms-gateway'});
MERGE (fn5_6:Function {id: 'fn-retry-sms', name: 'retry_failed_sms', signature: 'retry_failed_sms(id: str) -> bool', file_id: 'file-sms-gateway'});
MATCH (f:File {id: 'file-sms-gateway'}), (fn:Function) WHERE fn.id IN ['fn-dispatch-sms', 'fn-retry-sms'] MERGE (f)-[:DEFINES]->(fn);

// --- 9. IDENTITIES & PERMISSIONS (ATTACK PATH: payments-api asset -> identity -> permission -> CrownJewel) ---
MERGE (i1:Identity {id: 'ident-payments-sa', name: 'sa-payments-engine@fintech-gcp.iam', type: 'ServiceAccount', principal_type: 'IAM_SERVICE_ACCOUNT'});
MERGE (i2:Identity {id: 'ident-db-admin', name: 'role-rds-pg-superuser', type: 'DatabaseRole', principal_type: 'DB_ROLE'});
MERGE (i3:Identity {id: 'ident-auth-sa', name: 'sa-auth-service@k8s.fintech', type: 'ServiceAccount', principal_type: 'K8S_SERVICE_ACCOUNT'});

MERGE (p1:Permission {id: 'perm-ledger-admin', name: 'ledger.transactions.write', action: 'WRITE', resource: 'PaymentLedger'});
MERGE (p2:Permission {id: 'perm-pii-decrypt', name: 'kms.decrypt.pii', action: 'DECRYPT', resource: 'CustomerPIIStore'});
MERGE (p3:Permission {id: 'perm-kms-signer', name: 'kms.keys.sign', action: 'SIGN', resource: 'AuthSecrets'});

// Identity -> Permission
MATCH (i:Identity {id: 'ident-payments-sa'}), (p:Permission {id: 'perm-ledger-admin'}) MERGE (i)-[:HAS_PERMISSION]->(p);
MATCH (i:Identity {id: 'ident-payments-sa'}), (p:Permission {id: 'perm-pii-decrypt'}) MERGE (i)-[:HAS_PERMISSION]->(p);
MATCH (i:Identity {id: 'ident-db-admin'}), (p:Permission {id: 'perm-pii-decrypt'}) MERGE (i)-[:HAS_PERMISSION]->(p);
MATCH (i:Identity {id: 'ident-auth-sa'}), (p:Permission {id: 'perm-kms-signer'}) MERGE (i)-[:HAS_PERMISSION]->(p);

// Permission -> CrownJewel
MATCH (p:Permission {id: 'perm-ledger-admin'}), (cj:CrownJewel {id: 'cj-payment-ledger'}) MERGE (p)-[:GRANTS_ACCESS_TO]->(cj);
MATCH (p:Permission {id: 'perm-pii-decrypt'}), (cj:CrownJewel {id: 'cj-customer-pii'}) MERGE (p)-[:GRANTS_ACCESS_TO]->(cj);
MATCH (p:Permission {id: 'perm-kms-signer'}), (cj:CrownJewel {id: 'cj-auth-secrets'}) MERGE (p)-[:GRANTS_ACCESS_TO]->(cj);

// payments-api Asset -> Identity (Crucial attack path link)
MATCH (a:Asset {id: 'asset-payments-prod-01'}), (i:Identity {id: 'ident-payments-sa'}) MERGE (a)-[:USES_IDENTITY]->(i);
MATCH (a:Asset {id: 'asset-auth-prod-01'}), (i:Identity {id: 'ident-auth-sa'}) MERGE (a)-[:USES_IDENTITY]->(i);
MATCH (a:Asset {id: 'asset-payments-db-01'}), (i:Identity {id: 'ident-db-admin'}) MERGE (a)-[:USES_IDENTITY]->(i);

// Permission grants access to Asset as well
MATCH (p:Permission {id: 'perm-ledger-admin'}), (a:Asset {id: 'asset-payments-db-01'}) MERGE (p)-[:GRANTS_ACCESS_TO]->(a);

// --- 10. PAST INCIDENTS, ACTIONS, RUNBOOK STEPS & MEMORY EPISODES (3 Incidents) ---

// Past Incident 1: payments-api (WITH A FAILED RUNBOOK STEP!)
MERGE (inc1:Incident {
    id: 'inc-2024-0821',
    title: 'Payments API Ingress Exploit & Latency Spike',
    service_id: 'svc-payments-api',
    severity: 'CRITICAL',
    status: 'RESOLVED',
    created_at: '2024-08-21T14:32:00Z',
    resolved_at: '2024-08-21T16:05:00Z'
});
MATCH (inc:Incident {id: 'inc-2024-0821'}), (s:Service {id: 'svc-payments-api'}) MERGE (inc)-[:AFFECTS]->(s);

MERGE (act1_1:Action {id: 'act-2024-0821-isolate', type: 'ISOLATE_HOST', target: 'asset-payments-prod-01', status: 'SUCCESS', executed_at: '2024-08-21T14:35:00Z'});
MERGE (act1_2:Action {id: 'act-2024-0821-ticket', type: 'OPEN_TICKET', target: 'JIRA-SEC-412', status: 'SUCCESS', executed_at: '2024-08-21T14:36:00Z'});
MERGE (act1_3:Action {id: 'act-2024-0821-page', type: 'PAGE_ONCALL', target: 'oncall-payments', status: 'SUCCESS', executed_at: '2024-08-21T14:36:30Z'});
MERGE (act1_4:Action {id: 'act-2024-0821-egress', type: 'LOCKDOWN_EGRESS', target: 'vpc-subnet-payments', status: 'SUCCESS', executed_at: '2024-08-21T14:48:00Z'});

MATCH (inc:Incident {id: 'inc-2024-0821'}), (a:Action) WHERE a.id IN ['act-2024-0821-isolate', 'act-2024-0821-ticket', 'act-2024-0821-page', 'act-2024-0821-egress'] MERGE (inc)-[:HAS_ACTION]->(a);

// Runbook steps for Incident 1 (Step 2 FAILED!)
MERGE (rb1_1:RunbookStep {id: 'step-isolate-prod-node', name: 'Isolate affected node', step_number: 1, status: 'SUCCESS', command: 'kubectl cordon node-payments-prod-01'});
MERGE (rb1_2:RunbookStep {id: 'step-block-ingress-traffic', name: 'Apply strict WAF ingress drop rule', step_number: 2, status: 'FAILED', failure_reason: 'WAF global ingress drop rule caused billing-worker webhook drops and cascading checkout timeouts'});
MERGE (rb1_3:RunbookStep {id: 'step-switch-egress-lockdown', name: 'Switch to VPC security group egress lockdown', step_number: 3, status: 'SUCCESS', notes: 'Subnet-level isolation preserved internal webhook loop while blocking outbound data exfiltration'});

MATCH (inc:Incident {id: 'inc-2024-0821'}), (rb:RunbookStep) WHERE rb.id IN ['step-isolate-prod-node', 'step-block-ingress-traffic', 'step-switch-egress-lockdown'] MERGE (inc)-[:FOLLOWS]->(rb);

// MemoryEpisode for Incident 1
MERGE (mem1:MemoryEpisode {
    id: 'mem-ep-payments-01',
    incident_id: 'inc-2024-0821',
    service: 'payments-api',
    title: 'Payments API Ingress Block Failure & Subnet Lockdown Fallback',
    summary: 'When responding to attacks on payments-api, applying strict WAF ingress drop rule failed because it broke downstream billing worker callbacks. Commander switched runbook step 2 to VPC subnet egress lockdown which successfully isolated the asset without causing checkout failures.',
    key_takeaway: 'Avoid global WAF ingress drop on payments-api; switch runbook step to VPC security group egress lockdown.',
    lesson_learned: 'WAF block drops legitimate webhooks; use VPC security group egress lockdown instead',
    recommended_action: 'LOCKDOWN_EGRESS'
});
MATCH (inc:Incident {id: 'inc-2024-0821'}), (m:MemoryEpisode {id: 'mem-ep-payments-01'}) MERGE (inc)-[:REMEMBERS]->(m);
MATCH (m:MemoryEpisode {id: 'mem-ep-payments-01'}), (inc:Incident {id: 'inc-2024-0821'}) MERGE (m)-[:SIMILAR_TO]->(inc);

// Past Incident 2: auth-service
MERGE (inc2:Incident {
    id: 'inc-2024-0715',
    title: 'Auth Service Token Leakage & Emergency Key Rotation',
    service_id: 'svc-auth-service',
    severity: 'HIGH',
    status: 'RESOLVED',
    created_at: '2024-07-15T09:10:00Z',
    resolved_at: '2024-07-15T10:45:00Z'
});
MATCH (inc:Incident {id: 'inc-2024-0715'}), (s:Service {id: 'svc-auth-service'}) MERGE (inc)-[:AFFECTS]->(s);

MERGE (act2_1:Action {id: 'act-2024-0715-rotate', type: 'ROTATE_KMS_KEY', target: 'AuthSecrets', status: 'SUCCESS', executed_at: '2024-07-15T09:20:00Z'});
MERGE (act2_2:Action {id: 'act-2024-0715-flush', type: 'FLUSH_SESSIONS', target: 'redis-payments-cache-01', status: 'SUCCESS', executed_at: '2024-07-15T09:25:00Z'});
MATCH (inc:Incident {id: 'inc-2024-0715'}), (a:Action) WHERE a.id IN ['act-2024-0715-rotate', 'act-2024-0715-flush'] MERGE (inc)-[:HAS_ACTION]->(a);

MERGE (rb2_1:RunbookStep {id: 'step-auth-rotate', name: 'Trigger KMS key rotation', step_number: 1, status: 'SUCCESS'});
MERGE (rb2_2:RunbookStep {id: 'step-auth-flush', name: 'Invalidate active JWT sessions', step_number: 2, status: 'SUCCESS'});
MATCH (inc:Incident {id: 'inc-2024-0715'}), (rb:RunbookStep) WHERE rb.id IN ['step-auth-rotate', 'step-auth-flush'] MERGE (inc)-[:FOLLOWS]->(rb);

MERGE (mem2:MemoryEpisode {
    id: 'mem-ep-auth-01',
    incident_id: 'inc-2024-0715',
    service: 'auth-service',
    title: 'Auth Service Signing Key Rotation',
    summary: 'Leaked JWT secret required immediate key rotation and session cache invalidation. Succeeded within 35 minutes.',
    key_takeaway: 'Dual-phase key rotation prevents valid users from facing login loop errors.',
    lesson_learned: 'Rotate KMS key and purge session cache simultaneously',
    recommended_action: 'ROTATE_KMS_KEY'
});
MATCH (inc:Incident {id: 'inc-2024-0715'}), (m:MemoryEpisode {id: 'mem-ep-auth-01'}) MERGE (inc)-[:REMEMBERS]->(m);
MATCH (m:MemoryEpisode {id: 'mem-ep-auth-01'}), (inc:Incident {id: 'inc-2024-0715'}) MERGE (m)-[:SIMILAR_TO]->(inc);

// Past Incident 3: billing-worker
MERGE (inc3:Incident {
    id: 'inc-2024-0902',
    title: 'Billing Worker RabbitMQ Dead Letter Backpressure',
    service_id: 'svc-billing-worker',
    severity: 'HIGH',
    status: 'RESOLVED',
    created_at: '2024-09-02T11:00:00Z',
    resolved_at: '2024-09-02T12:30:00Z'
});
MATCH (inc:Incident {id: 'inc-2024-0902'}), (s:Service {id: 'svc-billing-worker'}) MERGE (inc)-[:AFFECTS]->(s);

MERGE (act3_1:Action {id: 'act-2024-0902-pause', type: 'PAUSE_CONSUMER', target: 'rabbitmq-notif-cluster-01', status: 'SUCCESS', executed_at: '2024-09-02T11:10:00Z'});
MERGE (act3_2:Action {id: 'act-2024-0902-drain', type: 'DRAIN_QUEUE', target: 'billing-dlq', status: 'SUCCESS', executed_at: '2024-09-02T11:30:00Z'});
MATCH (inc:Incident {id: 'inc-2024-0902'}), (a:Action) WHERE a.id IN ['act-2024-0902-pause', 'act-2024-0902-drain'] MERGE (inc)-[:HAS_ACTION]->(a);

MERGE (rb3_1:RunbookStep {id: 'step-pause-queue', name: 'Pause queue ingestion', step_number: 1, status: 'SUCCESS'});
MERGE (rb3_2:RunbookStep {id: 'step-drain-dlq', name: 'Drain corrupt payload messages to DLQ', step_number: 2, status: 'SUCCESS'});
MATCH (inc:Incident {id: 'inc-2024-0902'}), (rb:RunbookStep) WHERE rb.id IN ['step-pause-queue', 'step-drain-dlq'] MERGE (inc)-[:FOLLOWS]->(rb);

MERGE (mem3:MemoryEpisode {
    id: 'mem-ep-billing-01',
    incident_id: 'inc-2024-0902',
    service: 'billing-worker',
    title: 'Billing Worker Dead Letter Queue Mitigation',
    summary: 'Corrupt invoice payload caused repeating consumer crashes. Paused consumers and rerouted poisoned messages to DLQ.',
    key_takeaway: 'Pause consumers before inspecting poison pill messages to prevent memory crashes.',
    lesson_learned: 'Drain poison messages into dead letter queue before resuming consumers',
    recommended_action: 'DRAIN_QUEUE'
});
MATCH (inc:Incident {id: 'inc-2024-0902'}), (m:MemoryEpisode {id: 'mem-ep-billing-01'}) MERGE (inc)-[:REMEMBERS]->(m);
MATCH (m:MemoryEpisode {id: 'mem-ep-billing-01'}), (inc:Incident {id: 'inc-2024-0902'}) MERGE (m)-[:SIMILAR_TO]->(inc);
