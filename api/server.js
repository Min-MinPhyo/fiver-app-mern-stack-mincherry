import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv"
import jwt from "jsonwebtoken"
import cookieParser from "cookie-parser";
import cors from "cors"
dotenv.config();
const app = express();

const connect=async()=>{
    try {
        await mongoose.connect(process.env.MONGO_URL);
        console.log("connecetd database");
      } catch (error) {
        console.log(error)
      }
      
}

// import route
import authRoute from "./routes/auth.route.js"
import userRoute from "./routes/user.route.js"
import gigRoute from "./routes/gig.route.js"
import orderRoute from "./routes/order.route.js"
import conversationRoute from "./routes/conversation.route.js"
import messageRoute from "./routes/message.route.js"
import reviewRoute from "./routes/review.route.js"

app.use(express.json())
app.use(cookieParser())
app.use(cors({origin:"http://localhost:5173",credentials:true}))
// app.use(cors())

app.use("/api/auth",authRoute)
app.use("/api/users",userRoute)
app.use("/api/gigs",gigRoute)
app.use("/api/orders",orderRoute)
app.use("/api/conversations",conversationRoute)
app.use("/api/messages",messageRoute)
app.use("/api/reviews",reviewRoute)


app.use((err,req,res,next)=>{
      const errorStatus=err.status || 500
      const errorMessage=err.message || "Something Went Wrong"
      
      return res.status(errorStatus).send(errorMessage)
})


app.listen(8800, () => {
  connect()
  console.log("server runnn in port 8800");
});
