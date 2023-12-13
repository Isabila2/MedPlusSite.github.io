////////////////////////////////// Login

const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const port = 3000;
const app = express();


// Configurar a conexão com o banco de dados MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'phpmyadmin',
  password: 'isabila',
  database: 'medical',
});

// Configurar o middleware bodyParser
app.use(bodyParser.urlencoded({ extended: true }));

// Configurar sessões
app.use(session({ secret: 'secreto', resave: false, saveUninitialized: false }));

// Inicializar o Passport
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Configurar a estratégia de autenticação local
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      console.log('Tentando autenticar usuário:', username);
      const [rows] = await db.promise().query('SELECT * FROM user WHERE username = ?', [username]);
      const user = rows[0];

      if (!user) {
        console.log('Usuário não encontrado:', username);
        return done(null, false, { message: 'Usuário não encontrado.' });
      }

      // Verificar a senha usando bcrypt
      const isPasswordValid = await bcrypt.compare(password, user.password);
      
      if (!isPasswordValid) {
        console.log('Senha incorreta para o usuário:', username);
        return done(null, false, { message: 'Senha incorreta.' });
      }
      console.log('Usuário autenticado com sucesso:', username);
      return done(null, user);
    } catch (err) {
      console.error('Erro durante a autenticação:', err);
      return done(err);
    }
  }
));

app.get('/agendar', (req, res) => {
  if (req.session.loggedin) {
 if (req.session.usertype === "Paciente") {
      console.log("Redirecionando o Paciente logado");    
      res.render('agendar', { req: req }); // Use o mecanismo de visualização que preferir
     
    }
  } else {
    console.log("Usuário não logado (/consultas)");        
      res.redirect('/');
  }
});


  // Lógica para a rota "/consulta"

app.get('/admin', (req, res) => {
    console.log('Acessando a rota /admin');

   if (req.session.loggedin) {
        if (req.session.usertype === "Administrador") {

            // Consulta para médicos
            const queryMedicos = 'SELECT * FROM médicos';
            db.query(queryMedicos, (errMedicos, resultsMedicos) => {
                if (errMedicos) {
                    console.error('Erro ao buscar dados dos médicos:', errMedicos);
                    return res.status(500).send(`Erro ao buscar dados dos médicos: ${errMedicos.message}`);
                }

                // Consulta para pacientes
                const queryPacientes = 'SELECT * FROM pacientes';
                db.query(queryPacientes, (errPacientes, resultsPacientes) => {
                    if (errPacientes) {
                        console.error('Erro ao buscar dados dos pacientes:', errPacientes);
                        return res.status(500).send(`Erro ao buscar dados dos pacientes: ${errPacientes.message}`);
                    }

                    // Renderiza a página e passa os resultados para cada tabela
                    res.render('admin', {
                        dadosMedicos: Array.isArray(resultsMedicos) ? resultsMedicos : [],
                        dadosPacientes: Array.isArray(resultsPacientes) ? resultsPacientes : []
                    });
                });
            });
        } else {
            res.redirect('/');
        }
    } else {
        res.redirect('/');
    }
});

app.get('/cadastromed', (req, res) => {
  res.render('cadastromed'); // Use o mecanismo de visualizacao que preferir
});

app.get('/registro_existe', (req, res) => {
    res.render('registro_existe', { req: req });
});

app.get('/registro_err', (req, res) => {
    res.render('registro_err', { req: req });
});

app.get('/registro_ok', (req, res) => {
    res.render('registro_ok', { req: req });
});

app.get('/login_err', (req, res) => {
    res.render('login_err', { req: req });
});
 
app.get('/login_credenciais', (req, res) => {
    res.render('login_credenciais', { req: req });
});
 
app.get('/consulta_err', (req, res) => {
    res.render('consulta_err', { req: req });
});

app.get('/consulta_ok', (req, res) => {
    res.render('consulta_ok', { req: req });
});

app.get('/marcar_consulta', (req, res) => {
    res.render('marcar_consulta', { req: req });
});

app.post('/consultamarca', (req, res) => {
  res.redirect('/agendar');
});

app.get('/homeMedico', (req, res) => {
if (req.session.loggedin) {
   if (req.session.usertype === "Médico") {
    res.render('homeMedico', { req: req });
}
}
});

app.get('/homePaciente', (req, res) => {
if (req.session.loggedin) {
   if (req.session.usertype === "Paciente") {
    res.render('homePaciente', { req: req });
}
}
});

app.post('/sucessoConsulta', (req, res) => {
  res.redirect('/homeMedico');
});

app.post('/erroconsulta', (req, res) => {
  res.redirect('/');
});

app.post('/erroregistro', (req, res) => {
  res.redirect('/formulario');
});

app.post('/errologin', (req, res) => {
  res.redirect('/login');
});

app.post('/logout', (req, res) => {
    console.log('Deslogando');
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.get('/consultaspac', (req, res) => {
   console.log('Acessando a rota /consultasPaciente');

   if (req.session.loggedin && req.session.usertype === "Paciente") {
      const nomepaciente = req.session.nomepaciente;
      const query = 'SELECT * FROM agendamentos WHERE nomepaciente = ?';

      db.query(query, [nomepaciente], (err, results) => {
         if (err) {
            console.error('Erro ao buscar dados de consulta:', err);
            return res.status(500).send(`Erro ao buscar dados de consulta: ${err.message}`);
         }

         console.log('Resultados da consulta:', results);

         const dadosConsultas = Array.isArray(results) ? results : [];
         res.render('consultaspac', { dadosConsultas });
      });
   } else {
      // Lógica para lidar com o médico não autenticado
      res.status(401).send('Acesso não autorizado.');
   }
});

app.get('/consultasmedi', (req, res) => {
   console.log('Acessando a rota /consultasmedi');

   if (req.session.loggedin && req.session.usertype === "Médico") {
      const especialidade = req.session.especialidade;
      const query = 'SELECT * FROM agendamentos WHERE especialidade = ?';

      db.query(query, [especialidade], (err, results) => {
         if (err) {
            console.error('Erro ao buscar dados de consulta:', err);
            return res.status(500).send(`Erro ao buscar dados de consulta: ${err.message}`);
         }

         console.log('Resultados da consulta:', results);

         const dadosConsultas = Array.isArray(results) ? results : [];
         res.render('consultasmedi', { dadosConsultas });
      });
   } else {
      // Lógica para lidar com o médico não autenticado
      res.status(401).send('Acesso não autorizado.');
   }
});

// Marcar Consultas - Removi uma função desnecessária
app.post('/marcarConsulta', async (req, res) => {
  const { nomepaciente, especialidade, hora, dataconsulta, comentario } = req.body;
  console.log(`${nomepaciente}, ${especialidade}, ${hora}, ${dataconsulta}, ${comentario}`);
  // Inserir a nova consulta no banco de dados
  const SQL = 'INSERT INTO agendamentos (nomepaciente, especialidade, hora, dataconsulta, comentario) VALUES (?, ?, ?, ?, ?)';
  db.query(SQL, [nomepaciente, especialidade, hora, dataconsulta, comentario], (err, result) => {
    if (err) {
      console.error('Erro ao cadastrar consulta:', err);
      res.status(500).send('Erro ao cadastrar consulta.');
    } else {
      console.log('Consulta cadastrada com sucesso!');
      
     res.redirect('/marcar_consulta'); 
    }
  });
});

app.post('/confirmarConsulta', (req, res) => {
  const idConsulta = req.body.idConsulta;
 console.log('ID da Consulta:', idConsulta);
  // Buscar consulta na tabela de agendamentos
  const queryConsulta = 'SELECT * FROM agendamentos WHERE idConsulta = ?';
  
 db.query(queryConsulta, [idConsulta], (err, results) => {
    if (err) {
      console.error('Erro ao buscar consulta:', err);
      return res.status(500).json({ error: 'Erro ao confirmar a consulta.' });
    }

    if (!results || results.length === 0) {
      console.error('Consulta não encontrada.');
      return res.status(404).json({ error: 'Consulta não encontrada.' });
    }

    const consulta = results[0];

    // Exibindo as informações da consulta no console
    console.log('Coletando informações ', consulta.nomepaciente, ':', consulta.especialidade, ':', consulta.dataconsulta, ':', consulta.hora, ':', consulta.comentario);

    // O restante do seu código permanece inalterado...



    // Inserir consulta confirmada na tabela de consultas
    const queryConfirmar = 'INSERT INTO consultas (nomepaciente, especialidade, dataconsulta, hora, comentario) VALUES (?, ?, ?, ?, ?)';
    const valuesConfirmar = [consulta.nomepaciente, consulta.especialidade, consulta.dataconsulta, consulta.hora, consulta.comentario];
    
    db.query(queryConfirmar, valuesConfirmar, (errConfirmar) => {
      if (errConfirmar) {
        console.error('Erro ao confirmar a consulta:', errConfirmar);
        return res.status(500).json({ error: 'Erro ao confirmar a consulta .' });
      }

      // Remover consulta da tabela de agendamentos
      const queryRemover = 'DELETE FROM agendamentos WHERE idConsulta = ?';
      db.query(queryRemover, [idConsulta], (errRemover) => {
        if (errRemover) {
          console.error('Erro ao remover a consulta da tabela de agendamentos:', errRemover);
          return res.status(500).json({ error: 'Erro ao confirmar a consulta.' });
        }

        res.redirect('/consulta_ok');
      });
    });
  });
});


// Função para cadastrar um novo usuário
app.post('/register', async (req, res) => {
  const { email, senha, nome } = req.body;

  try {
    // Verificar se o usuário já existe
    const [existingUsers] = await db.promise().query('SELECT * FROM pacientes WHERE email = ?', [email]);

    if (existingUsers.length > 0) {
      // Usuário já existe
      return res.redirect('/registro_existe');
    }

    // Inserir o novo usuário no banco de dados
    const [result] = await db.promise().query('INSERT INTO pacientes (nome, senha, email) VALUES (?, SHA1(?), ?)', [nome, senha, email]);

    if (result.insertId) {
      // Inserção bem-sucedida
      return res.redirect('/registro_sucesso');
    } else {
      // Erro durante a inserção
      return res.redirect('/registro_err');
    }
  } catch (error) {
    // Lidar com erros
    console.error('Erro durante o cadastro do usuário:', error);
    return res.redirect('/registro_err');
  }
});

// Nova rota para registro de usuário
app.post('/register', async (req, res) => {
  const { email, senha, nome, tipo } = req.body;

  try {
    const userId = await registerUser(email, senha, nome, tipo);
    // Usuário cadastrado com sucesso
    console.log(nome,'foi cadastrado com sucesso com email:',email,' e senha:',senha,' e é um', tipo)
    res.status(200).redirect(`/login`);
  } catch (error) {
    // Lidar com erros de cadastro
    res.status(400).send(`Erro no cadastro: ${error.message}`);
  }
});

//Serializar
passport.serializeUser((user, done) => {
  console.log('Serializando usuário:', user.id);
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  console.log('Desserializando usuário com ID:', id);
  try {
    const [rows] = await db.promise().query('SELECT * FROM user WHERE id = ?', [id]);
    const user = rows[0];

    if (!user) {
      console.log('Usuário não encontrado para ID:', id);
      return done(null, false); // Usuário não encontrado
    }

    console.log('Usuário recuperado:', user);
    done(null, user);
  } catch (err) {
    console.error('Erro durante a desserialização:', err);
    done(err);
  }
});


// Configurar EJS como o motor de visualizacao
app.set('view engine', 'ejs');

// Rota para a pagina index
app.get('/', (req, res) => {
  res.render('index'); // Use o mecanismo de visualizacao que preferir
});


app.get('/login', (req, res) => {
  res.render('login'); // Use o mecanismo de visualização que preferir
});
// Ação de Login Redirecionamento inteligente.
app.post('/login', (req, res) => {
    const { email, senha } = req.body;
    console.log('Credenciais recebidas:', email, senha);

    // Verificar na tabela de pacientes
    const queryPacientes = 'SELECT * FROM pacientes WHERE email = ? AND senha = SHA1(?)';
    db.query(queryPacientes, [email, senha], (err, results) => {
        if (err) {
            console.error('Erro ao verificar o login:', err);
            return res.redirect('/login_err');
        }

        if (results && results.length > 0) {
            const usuario = results[0];
            console.log('Login bem sucedido de Paciente: ' + usuario.nomepaciente);
            req.session.loggedin = true;
            req.session.username = usuario.nomepaciente;
            req.session.usertype = 'Paciente';
            req.session.nomepaciente = usuario.nomepaciente;
            return res.status(200).redirect('/homePaciente');
        } else {
            // Se não encontrado na tabela de pacientes, verificar na tabela de médicos
            const queryMedicos = 'SELECT * FROM médicos WHERE email = ? AND senha = SHA1(?)';
            db.query(queryMedicos, [email, senha], (err, results) => {
                // Código semelhante ao bloco anterior, apenas muda a tabela e o tipo de usuário

                if (err) {
                    console.error('Erro ao verificar o login:', err);
                    return res.redirect('/login_err');
                }

                if (results && results.length > 0) {
                    const usuario = results[0];
                    console.log('Login bem sucedido de Médico: ' + usuario.nome);
                    req.session.loggedin = true;
                    req.session.username = usuario.nome;
                    req.session.usertype = 'Médico';
                    req.session.especialidade = usuario.especialidade;
                    return res.status(200).redirect('/homeMedico');
                } else {
                    // Se não encontrado na tabela de médicos, verificar na tabela de admins
                    const queryAdmins = 'SELECT * FROM admins WHERE email = ? AND senha = ?';
                    db.query(queryAdmins, [email, senha], (err, results) => {
                        // Código semelhante ao bloco anterior, apenas muda a tabela e o tipo de usuário

                        if (err) {
                            console.error('Erro ao verificar o login:', err);
                            return res.redirect('/login_err');
                        }

                        if (results && results.length > 0) {
                            const usuario = results[0];
                            console.log('Login bem sucedido de Admin: ' + usuario.nome);
                            req.session.loggedin = true;
                            req.session.username = usuario.nome;
                            req.session.usertype = 'Administrador';
                            return res.redirect('/admin');
                        } else {
                            console.log('Credenciais inválidas');
                            return res.redirect('/login_credenciais');
                        }
                    });
                }
            });
        }
    });
});



// Rota para a página de login
app.get('/login', (req, res) => {
  res.render('login'); // Use o mecanismo de visualização que preferir
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard', // Redirecionamento após login bem-sucedido
  failureRedirect: '/login',    // Redirecionamento após falha de login
  failureFlash: true,          // Permite o uso de mensagens flash
}));


// Rota protegida - exemplo da página de dashboard
app.get('/dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    res.send('Você está logado.');
    console.log('Usuário logado');
  } else {
    console.log('Usuário inválido');
    res.redirect('/login');
  }
});

app.get('/formulario', (req, res) => {
  res.render('formulario'); // Use o mecanismo de visualização que preferir

});

// Rota protegida - exemplo da página de dashboard
//app.get('/fechar.html', (req, res) => {
 // if (req.isAuthenticated()) {
  //  res.send('Você está logado.');
   // console.log('Usuário logado');
  
    //res.redirect('window.close;');
 // } else {
   // console.log('Usuário inválido');
   // res.redirect('/login');
 // }
//});
//testes 

// Servir arquivos estáticos
app.use(express.static(__dirname + '/'));

// Iniciar o servidor
app.listen(port, () => {
  console.log(`Servidor Express está rodando na porta ${port}`);
});
