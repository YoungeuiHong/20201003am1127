var express = require('express');
var router = express.Router();

require('dotenv').config();

const pool = require('../utils/mysql');

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const isLoggedin = require('../utils/isLoggedin');


/* GET users listing. */
router.get('/', async function(req, res, next) {
  
  try {
    const connection = await pool.getConnection();
    const [results] = await connection.query('SELECT * FROM user_TB');
    connection.release();
    res.json({status: 200, arr: results});
  } catch(err) {
    console.log(err);
    res.json({status: 500, msg: '서버 에러'});
    
  }
 
});

/* router.post('/', async function(req, res, next) {
  
  try {
    const {name, money, email, pwd, salad, juice, viet, mara, shell, avocado, peach, banana, search} = req.body;
    const connection = await pool.getConnection();
    const pwdSalt = (await crypto.randomBytes(64)).toString('base64');
    const hashedPwd = (crypto.pbkdf2Sync(pwd, pwdSalt, 100000, 64, "SHA512")).toString('base64');
    await connection.query('INSERT INTO user_TB(name, money, email, hashed_pwd, pwd_salt, salad, juice, viet, mara, shell, avocado, peach, banana, search) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [name, money, email, hashedPwd, pwdSalt, salad, juice, viet, mara, shell, avocado, peach, banana, search]);
    res.json({status: 201, msg: '저장 성공!'});
  } catch(err) {
    console.log(err);
    res.json({status: 500, msg: '서버 에러'});
    
  }
 
}); */

/*router.post('/', async function(req, res, next) {
  
  try {
    const {name, money, email, pwd} = req.body;
    const connection = await pool.getConnection();
    const pwdSalt = (await crypto.randomBytes(64)).toString('base64');
    const hashedPwd = (crypto.pbkdf2Sync(pwd, pwdSalt, 100000, 64, "SHA512")).toString('base64');
    await connection.query('INSERT INTO user_TB(name, money, email, hashed_pwd, pwd_salt) VALUES(?,?,?,?,?)', [name, money, email, hashedPwd, pwdSalt]);
    res.json({status: 201, msg: '저장 성공!'});
  } catch(err) {
    console.log(err);
    res.json({status: 500, msg: '서버 에러'});
    
  }
 
});*/

router.post('/', async function(req, res, next) {
  
  try {
    const {email, salad, juice, viet, mara, shell, avocado, peach, banana, search, address} = req.body;
    const connection = await pool.getConnection();
    await connection.query('INSERT INTO user_TB(email, salad, juice, viet, mara, shell, avocado, peach, banana, search, address) VALUES(?,?,?,?,?,?,?,?,?,?,?)', [email, salad, juice, viet, mara, shell, avocado, peach, banana, search, address]);
    res.json({status: 201, msg: '저장 성공!'});
  } catch(err) {
    console.log(err);
    res.json({status: 500, msg: '서버 에러'});
    
  }
 
});

router.post('/login', async function(req, res, next) {
  
  try {
    const {email, pwd} = req.body;
    const connection = await pool.getConnection();
    const [users] = await connection.query('SELECT * from user_TB WHERE email = ?', [email]);
    if(users.length===0) {
      return res.json({status: 401, msg: '가입되지 않은 이메일입니다'});
    }
    const user = users[0];
    const hashedPwd = (crypto.pbkdf2Sync(pwd, user.pwd_salt, 100000, 64, 'SHA512')).toString('base64');
    if (user.hashed_pwd !== hashedPwd) {
      return res.json({status: 401, msg: '일치하지 않는 비밀번호입니다'})
    }


    connection.release();
    const token = jwt.sign({id:user.ID}, process.env.JWT_SECRET, { expiresIn: '30d'})
    res.cookie('token', token);
    res.json({status: 200, token: token});
  } catch(err) {
    console.log(err);
    res.json({status: 500, msg: '서버 에러'});
    
  }
 
});


// GET users/4/profile 이렇게 되면 4의 프로파일을 담아오는 것
router.get('/:id/profile', isLoggedin, async function(req, res, next) {
  try {
    const userID = req.params.id;
    if (req.userId != userID) {
      return res.json({status: 401, msg: '넌 권한 없어!'})
    }
    const connection = await pool.getConnection();
    const [results] = await connection.query('SELECT * FROM user_TB WHERE ID=?', [userID]);
    connection.release();
    res.json({status: 200, arr: results});
  } catch(err) {
    console.log(err);
    res.json({status: 500, msg: '서버 에러'});
    
  }
 
});


module.exports = router;
