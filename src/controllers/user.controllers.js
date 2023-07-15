const catchError = require('../utils/catchError');
const User = require('../models/User');
const EmailCode = require('../models/EmailCode');
const { json } = require('express');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');
const jwt = require('jsonwebtoken');


const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const { email, password, firstName, lastName, country, image, frontBaseUrl} = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await User.create(
        { email, 
          password : hashedPassword, 
          firstName, 
          lastName, 
          country, 
          image
        }
    );

    const code = require('crypto').randomBytes(32).toString('hex');
    //const link = `${frontBaseUrl}/auth/verify/${code}`
	//mire profe, si en vez del link de arriba, envio cualquiera de los de abajo, funciona, 
	//pero lo deje como usted lo hizo para saber que pasa con el de arriba que no me funciona
   //const link = `https://user-auth-crud.onrender.com/users/verify/${code}`
	const link = `http://localhost:3000/auth/verify/${code}`

    await sendEmail({
		to: email, // Email del receptor
		subject: "Verification account Email", // asunto
		html: ` 
				<div>
						<h1>Verify your account</h1>
                        <p>click on the link bellow to verify your account</p>
                        <a href=${link}>Verify account link</a>
				</div>
		` // con backtics ``
    })

    EmailCode.create({
        code,
        userId : result.id
    })
    return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const { firstName, lastName, country, image } = req.body;
    const result = await User.update(
        { firstName, lastName, country, image },
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verify = catchError(async(req, res) => {
    const {code} = req.params;
    const findedUserCode = await EmailCode.findOne({where: {code}})
    if(!findedUserCode) return json.status(401).json({message : "Wrong code"})
    const user = await User.findByPk(findedUserCode.userId)
    user.isVerified = true;
    await user.save();
    await findedUserCode.destroy();
    return res.json(user)
});

const login = catchError(async(req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({where:{email}})
    if(!user) return res.status(401).json({message : "Wrong Credentials"})
    const isValid = await bcrypt.compare( password, user.password);
    if(!isValid) return res.status(401).json({message : "Wrong Credentials"})
    if(!user.isVerified) return res.status(401).json({message : "User Not Verified"})

    const token = jwt.sign(
		{ user}, // payload
		process.env.TOKEN_SECRET, // clave secreta
		//{ expiresIn: '5m' } // OPCIONAL: Tiempo en el que expira el token
    )

    return res.json({user, token})
});

const loggedUser = catchError(async(req, res) => {
    const user = req.user;
    return res.json(user)
})

const resetPassword = catchError(async(req, res) => {
    const {email, frontBaseUrl} = req.body;
    const findedUser = await User.findOne({where:{email}})
    if(!findedUser) return res.status(401).json({message : "Email does not exist"})
    const code = require('crypto').randomBytes(32).toString('hex');
    const link = `${frontBaseUrl}/auth/reset_password/${code}`

    await sendEmail({
		to: email, // Email del receptor
		subject: "Reset Email Password", // asunto
		html: ` 
				<div>
						<h1>Reset your password</h1>
                        <p>click on the link bellow to reset your account password</p>
                        <a href=${link}>Verify account link</a>
				</div>
		` // con backtics ``
    })

    EmailCode.create({
        code,
        userId : findedUser.id
    })

    return res.json({message : "We have sent you an email to reset your password"})
});


const newPassword = catchError(async(req, res) => {
    const {password} = req.body;
    const {code} = req.params;
    const findedUserCode = await EmailCode.findOne({where: {code}})
    if(!findedUserCode) return json.status(401).json({message : "Wrong code"})
    const user = await User.findByPk(findedUserCode.userId)
    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.save();
    return res.json({message : "Password changed successfully"})

});

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verify,
    login,
    loggedUser,
    resetPassword,
    newPassword
}
