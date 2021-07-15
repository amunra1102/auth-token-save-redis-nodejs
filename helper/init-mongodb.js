const mongoose = require('mongoose');

mongoose.connect(process.env.MONGO_URL, {
  useCreateIndex: true,
  useFindAndModify: false,
  useNewUrlParser: true,
  useUnifiedTopology: true
}, err => {
  if (err) {
    console.log(err.message);
    return;
  }

  console.log('mongodb connected');
});

mongoose.connection.on('connected', () => console.log('Mongoose connected to db'));

mongoose.connection.on('error', error => console.log(error.message));

mongoose.connection.on('disconnected', () => console.log('Mongoose connection is disconnected'));

process.on('SIGINT', async () => {
  await mongoose.connection.close();
  process.exit(0);
})
