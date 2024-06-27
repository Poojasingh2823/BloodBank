const mongoose = require('mongoose')
const colors = require('colors')

const connectDB = async() =>{
    try{
       await mongoose.connect(process.env.MONGO_URL)
       console.log(`Connected to mongodb Database ${mongoose.connection.host}`.bgCyan.white)
    }catch(error){
       console.log(`Mongodb Database error ${error}`.bgCyan.black)
    }

}

module.exports = connectDB