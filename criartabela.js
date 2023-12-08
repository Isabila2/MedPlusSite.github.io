CREATE TABLE consultas (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nomepaciente VARCHAR(255) NOT NULL,
  nomemedico VARCHAR(255) NOT NULL,
  horario TIME NOT NULL,
  dataconsulta DATE NOT NULL,
  hora DATETIME NOT NULL,
  motivo TEXT
);
