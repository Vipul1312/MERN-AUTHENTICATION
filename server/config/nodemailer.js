import nodemailer from 'nodemailer'

const transporter = nodemailer.createTransport({
    // host: 'smtp.resend.com',
    // port: 587,
    // secure:false,
    service: 'gmail',
    auth: {
        user:process.env.SMTP_USER,
        pass:process.env.SMTP_PASS,
    }
});

export default transporter;