const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const UserModel = require("../model/User.model")

class UserService {
    constructor(user){
        this.name = user.name;
        this.email = user.email;
        this.password= user.password;
    }

    isValid(field, validationRegEx){
        if(!field || !field.match(validationRegEx)){
            return false
        }
        return true
    }
    async getUserByEmail(email){
        const user = await UserModel.findOne({email: email})
        return user
    }
    async userExists(email){
        const user = await this.getUserByEmail(email)
        if(user){
            return true
        }
        return false
    }
    hashPassword(plainTextPassword){
        const saltRounds = 10;
        const salt = bcrypt.genSaltSync(saltRounds)
        const hashedPassword = bcrypt.hashSync(plainTextPassword, salt)
        return hashedPassword
    }
    async createUser(){
        return UserModel.create({
            name: this.name,
            email: this.email,
            passwordHash: this.hashPassword
        }).then((insertResult)=> insertResult)
    }
    async login(){
        const user = await this.getUserByEmail(this.email);
        if(!user){
            throw new Error("usuario não cadastrado")
        }
        if(bcrypt.compareSync(this.password, user.passwordHash)){
            const token = this.generateToken(user)
            return {token: token, user: user}
        }
        return false
    }
    generateToken(user){
        const signSecret = process.env.TOKEN_SIGN_SECRET;
        delete user.passwordHash;
        const token = jwt.sign(user.toJSON(), signSecret, { expiresIn: "6h" });
        return token;
    }
}

module.exports = UserService;