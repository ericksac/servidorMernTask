const Usuario = require('../models/Usuario');
const bcryptjs = require('bcryptjs');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

exports.crearUsuario = async (req, res) => {

    //Validar con express validator
    const errores = validationResult(req);
    if( !errores.isEmpty()){
        return res.status(400).json({errores: errores.array() });
    }

    //Extraer email y password
    const {email, password} = req.body;

    try {
        let usuario = await Usuario.findOne({email});

        if( usuario ){
            return res.status(400).json({ msg: 'El usuario ya existe'});
        }
        //guardar nuevo usuario
        usuario = new Usuario (req.body);
        
        const salt  = await bcryptjs.genSaltSync(10);
        usuario.password =  await bcryptjs.hashSync(password.toString(), salt);
        
        await usuario.save();

        //Crear y firmar el JWT
        const payload = {
            usuario:{
                id: usuario.id
            }
        };

        //firnar el JWT
        jwt.sign( payload, process.env.SECRETA, {
            expiresIn: 3600
        }, (error, token) =>{
            if(error) throw error;

            res.json({ token });
        });
    } catch (error) {
        console.log(error);
        res.status(400).send('Hubo un error')
    }
}