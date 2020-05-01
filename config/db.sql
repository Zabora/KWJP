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

CREATE TABLE IF NOT EXISTS `flashcard_sets` (
  'set_id' int(12) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  'set_name' varchar(100) DEFAULT NULL,
  PRIMARY KEY (`set_id`),
  KEY user_id(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `flashcard` (
  `id` int(16) NOT NULL AUTO_INCREMENT,
  'set_id' int(12) NOT NULL,
  'flashcard_name' varchar(100) NOT NULL,
  'answer' varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY set_id(set_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;