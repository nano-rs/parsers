# Apache Kafka samples

Sources:

- Elastic `kafka` integration pipeline test fixtures:
  https://github.com/elastic/integrations/blob/main/packages/kafka/data_stream/log/_dev/test/pipeline/test-server.log,
  https://github.com/elastic/integrations/blob/main/packages/kafka/data_stream/log/_dev/test/pipeline/test-server-2-0-0.log,
  https://github.com/elastic/integrations/blob/main/packages/kafka/data_stream/log/_dev/test/pipeline/test-controller.log and
  https://github.com/elastic/integrations/blob/main/packages/kafka/data_stream/log/_dev/test/pipeline/test-authlog.log
  (`server_starting`, `server_zookeeper_connecting`, `server_warn_meta_properties`,
  `server_group_metadata`, `server_fetch_error_info`, `controller_*`,
  `sasl_success_kerberos*`).
- Kafka source, the authorizer audit line: KRaft
  https://github.com/apache/kafka/blob/trunk/metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizerData.java
  (`Principal = ... is Denied operation = ... based on rule ...`) and the
  ZooKeeper-mode AclAuthorizer form (`is Denied Operation = ...`, no rule)
  (`authorizer_*`).
- Kafka source, the failed authentication line,
  https://github.com/apache/kafka/blob/trunk/clients/src/main/java/org/apache/kafka/common/network/Selector.java
  (`Failed {re-}authentication with {socket} (channelId=...) ({reason})`), with
  reasons from the SASL authenticators (`sasl_failed_*`, `ssl_failed_handshake`).
- Kafka broker lifecycle lines from `kafka.server.KafkaServer`,
  `kafka.server.KafkaRaftServer` and `kafka.server.BrokerServer`
  (`server_started`, `server_kraft_started`, `server_broker_transition_started`,
  `server_shutdown_completed`, `server_error_log_dir`, `server_fatal_halt`).
- `junk.json` is a JVM stderr line with no log4j prefix: fallback branch.

Principals, hosts and Kerberos realms are replaced with example values and
addresses with documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32).
