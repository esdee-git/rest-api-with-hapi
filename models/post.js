var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var CommentSchema = new Schema({
    text: String,
    user_id: Schema.Types.ObjectId
});

var PostSchema = new Schema({
    country: String,
    city: String,
    keyword_1: String,
    keyword_2: String,
    keyword_3: String,
    description: String,
    user_id: Schema.Types.ObjectId,
    comments: [CommentSchema]
});

module.exports = mongoose.model('Post', PostSchema, 'Post');
