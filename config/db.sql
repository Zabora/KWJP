CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) DEFAULT NULL,
  `surname` varchar(100) DEFAULT NULL,
  `pass` varchar(100) NOT NULL,
  `email` varchar(50) NOT NULL,
  `privileges` enum('admin','user') NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `recovery_tokens` (
  `id` int(11) NOT NULL AUTO_INCREMENT, -- identyfikator
  `user_id` int(11) NOT NULL, -- id użytkownika
  `token` varchar(128) NOT NULL, -- token, może być mniejszy?
  `gen_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, -- czas wygenerowania tokenu
  `exp_time` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP, -- czas użycia/wygaśnięcia tokenu
  `state` enum('active','expired','used') NOT NULL DEFAULT 'active', -- stan tokenu
  PRIMARY KEY (`id`),
  KEY `search` (`state`,`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;