-- MySQL dump 10.13  Distrib 5.5.54, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: keystone
-- ------------------------------------------------------
-- Server version	5.5.54-0ubuntu0.14.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user` (
  `id` varchar(64) NOT NULL,
  `name` varchar(255) NOT NULL,
  `extra` text,
  `password` varchar(128) DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT NULL,
  `domain_id` varchar(64) NOT NULL,
  `default_project_id` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ixu_user_name_domain_id` (`domain_id`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES ('336ee462935141789b680cc8a554a840','nova','{\"email\": \"sreenath.mm@poornam.com\", \"phone\":\"+919496341531\", \"two_factor_enabled\":\"True\"}','$6$rounds=10000$Ogit4RYkXYiA36dO$CwBWuWlr.nCssb.nkBTogsbjCS5L0Nu8eyWjnSUvGkN3qp97L.Mhz1NYviIMjhKfJ9E9po8Y0MnT0231TFSWo.',1,'default',NULL),('5d17f537b9d9426ba22320a80c5e8b7e','glance','{\"email\": \"sreenath.mm@poornam.com\", \"phone\":\"+919496341531\", \"two_factor_enabled\":\"True\"}','$6$rounds=10000$8NM4OEYUc6LjOh7/$5I2p5mOweDjGrI7p7yafU4CaiF20eSXF/dM5yYk8t3UiDLmkXZ137JVBUdGBDrmTzRPns3LF9nayJuHzdLwUb/',1,'default',NULL),('5e795c1eb63f4a0ca677428d89cacf9c','admin','{\"two_factor_enabled\": true, \"phone\": \"+919496341531\", \"secret_key\": \"LEXZZFSGE6XQ5AJ5\", \"email\": \"sreenath.mm@poornam.com\"}','$6$rounds=10000$kXGPq2omZ4vooLBX$KDKcScHOrCyemA1bfWU.N/SkO8x2w8mf5LiS7Y2Yzr7/MdvbnaxMpwxWV1VbyPXDDPEtLE.EvWmvkSZeFKpgw/',1,'default',NULL),('8296c534fbbe43c3959d37116f6fb4a7','neutron','{\"email\": \"sreenath.mm@poornam.com\", \"phone\":\"+919496341531\", \"two_factor_enabled\":\"True\"}','$6$rounds=10000$yRXOs8vQXYExkhu1$uGjubfUaoSj.fuu0xk3Kh/mRiFFjCGKvuetAqrxnuYktK7rvEa9SVankATILVJxukdZEe1Mi4XXkCAxyqN85u/',1,'default',NULL),('8e500248e5bc46b1abb6220428aca4bc','cinder','{\"email\": \"sreenath.mm@poornam.com\", \"phone\":\"+919496341531\", \"two_factor_enabled\":\"True\"}','$6$rounds=10000$eb70qNAvj0DfEG3h$zMeq.ZO37DujJBs2.0Hy4uPaHxoGKLeaGkdR0/F2GO5Uerw.z5LotJb2g3RSusODZPKI82EehgFqH7BPMcgKY0',1,'default',NULL),('afc72d1482fa4884b1f6aa47e512546b','demo','{\"email\": \"sreenath.mm@poornam.com\", \"phone\":\"+919496341531\", \"two_factor_enabled\":\"False\"}','$6$rounds=10000$ZdV5Qy8QjJXi5b5L$rSMEfBPEX8vQ0QvRkqMIpnv6i.jLoh6Q1cFYuyZTI7k2FQdjk6/bUIXmblk9VRa7BQfbUqHHFquTG8i/cECXm.',1,'default',NULL);
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2017-09-26 22:35:07
