'use strict';

const Hapi = require('hapi');
const Boom = require('boom');
var mongoose = require('mongoose');
var JWT = require('jsonwebtoken'); // used to sign our content
var port = 8000; //process.env.PORT;  // allow port to be set
var aguid = require('aguid') // https://github.com/ideaq/aguid
const Bcrypt = require('bcrypt');
var Joi = require('joi');
Joi.objectId = require('joi-objectid')(Joi);
var env = require('env2');
const Package = require('./package');
var HapiSwagger = require('hapi-swagger');

if (process.env.NODE_ENV === undefined) {
  env('config.env'); //note: heroku will use some port other than the one we requested
}

mongoose.connect(process.env.MONGOLAB_URI);

var PostModel = require('./models/post');
var UserModel = require('./models/user');

// Create a server with a host and port
const server = new Hapi.Server();
server.connection({
  port: process.env.PORT
});

const swaggerOptions = {
    info: {
            'title': Package.name,
            'version': Package.version,
        }
    };

function generateToken(req, GUID, userId, opts) { //from https://github.com/dwyl/learn-json-web-tokens/blob/master/example/lib/helpers.js
  opts = opts || {};

  // By default, expire the token after 7 days (7*24*60*60)
  // NOTE: the value for 'exp' needs to be in seconds since
  // the epoch as per the spec!
  var expiresDefault = Math.floor(new Date().getTime() / 1000) + 24 * 60 * 60; //expire after 24 hours

  var token = JWT.sign({
    auth: GUID,
    user_id: userId,
    agent: req.headers['user-agent'],
    exp: opts.expires || expiresDefault //s1 tested: expiration works fine
  }, process.env.JWT_SECRET);
  return token;
}

// bring your own validation function
var validate = function(decoded, request, callback) {

  return callback(null, true);
};

const validateSimpleAuth = function(request, username, password, callback) {
  // Bcrypt.compare(password, user.password, (err, isValid) => {
  //     callback(err, isValid, { id: user.id, name: user.name });
  // });

  var schema = {
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().regex(/^[a-zA-Z0-9]{3,30}$/).required(),
  };

  //var isValid = Joi.validate({ username: username, password: password }, schema, {abortEarly:true});

  return callback(null, true, {});
};

// Register bell and hapi-auth-cookie with the server
server.register([require('hapi-auth-jwt2'), require('bell'), require('inert'), require('vision'), 	{
		register: HapiSwagger,
		options: swaggerOptions
	}], function(err) {
  server.auth.strategy('jwt', 'jwt', {
    key: process.env.JWT_SECRET,
    validateFunc: validate,
    verifyOptions: {
      ignoreExpiration: false
    }
  });

  server.auth.strategy('facebook', 'bell', {
    provider: 'facebook',
    password: 'secret_cookie_encryption_password', //Use something more secure in production
    clientId: process.env.FB_CLIENT_ID, //'Here goes the ClientId',
    clientSecret: process.env.FB_CLIENT_SECRET, //'Here goes the ClientSecret',
    isSecure: false //Should be set to true (which is the default) in production
  });

  server.auth.default('jwt');

  server.route({
    method: 'GET',
    path: '/auth/facebook',
    config: {
      auth: 'facebook',
      tags: ['api'],
      description: 'authenticate user with facebook',
      handler: function(request, reply) {

        if (!request.auth.isAuthenticated) {
          return reply(Boom.unauthorized('Authentication failed: ' + request.auth.error.message));
        }

        //Just store the third party credentials in the session as an example. You could do something
        //more useful here - like loading or setting up an account (social signup).
        // request.auth.session.set(request.auth.credentials);
        //
        // return reply.redirect('/');

        var token = generateToken(request, request.auth.credentials, 0); //passing empty 'opt' param; todo: actual userId instead of 0

        return reply({
            text: 'Check Auth Header for your Token'
          })
          .header("Authorization", token).code(200);
      }
    }
  });

  server.route({
    method: 'POST',
    path: '/auth',
    config: {
      auth: false,
      tags: ['api'],
      description: 'authenticate user with email and password',
      validate: {
        payload: {
          email: Joi.string().email().lowercase().required(),
          password: Joi.string().required()
        }
      },
      handler: function(request, reply) {
        var schema = {
          email: Joi.string().email().lowercase().required(),
          password: Joi.string().required(),
        };
        var validationResult = Joi.validate(request.payload, schema, {
          abortEarly: true
        });
        if (validationResult.error !== null) {
          return reply(Boom.badRequest("Invalid payload in request"));
        }

        UserModel.findOne({
          email: request.payload.email
        }, function(error, user) {
          if (error) {
            reply(Boom.badImplementation('UserModel.findOne failed'));
          } else {
            if (!user) {
              return reply(Boom.unauthorized('invalid email'));
            }
            user.comparePassword(request.payload.password, function(err, isMatch) {
              if (err !== null) {
                return reply(Boom.badImplementation('auth failed'));
              }
              if (!isMatch) {
                return reply(Boom.unauthorized('invalid password'));
              }

              var token = generateToken(request, aguid(), user._id);

              return reply({
                  text: 'Check Auth Header for your Token'
                })
                .header("Authorization", token).code(200);
            });
          }
        });
      }
    }
  });

  server.route({
    method: 'POST',
    path: '/user',
    config: {
      tags: ['api'],
      description: 'create user account with email and password',
      auth: false,
      validate: {
        payload: {
          email: Joi.string().email().lowercase().required(),
          username: Joi.string().alphanum().min(3).max(30).optional(),
          password: Joi.string().required()
        }
      },
      handler: function(request, reply) {
        // Create mongodb user object to save it into database
        var user = new UserModel(request.payload);

        // Call save methods to save data into database
        // and pass callback methods to handle error
        user.save(function(error) {
          if (error) {
            return reply(Boom.badRequest('user.save failed: ' + error.message));
          } else {
            return reply().code(201);
          }
        });
      }
    }
  });

  server.route({
    method: 'POST',
    path: '/api/v1/post',
    config: {
      auth: 'jwt',
      // "tags" enable swagger to document API
      tags: ['api'],
      description: 'create post',
      // We use Joi plugin to validate request
      validate: {
        query: false,
        payload: {
          // Both name and age are required fields
          country: Joi.string().required(),
          city: Joi.string().required(),
          keyword_1: Joi.string().alphanum().required(),
          keyword_2: Joi.string().alphanum().required(),
          keyword_3: Joi.string().alphanum().required(),
          description: Joi.string().required()
        },
        headers: Joi.object({
             'authorization': Joi.string().required()
        }).unknown()
      }
    },
    handler: function(request, reply) {
      // Create mongodb user object to save it into database
      var payloadWithUserId = request.payload;
      try {
        var decoded = JWT.verify(request.headers.authorization, process.env.JWT_SECRET);
        payloadWithUserId.user_id = decoded.user_id;
      } catch(err) {
        return reply(Boom.badData('auth token is invalid'));
      }
      var post = new PostModel(request.payload);

      // Call save methods to save data into database
      // and pass callback methods to handle error
      post.save(function(error) {
        if (error) {
          reply(Boom.badImplementation('post.save failed'));
        } else {
          reply().code(201);
        }
      });
    }
  });

  server.route({
    method: 'GET',
    path: '/api/v1/post',
    config: {
      auth: 'jwt',
      // Include this API in swagger documentation
      tags: ['api'],
      description: 'get posts with keyword for country&city',
      validate: {
        query: {
          country: Joi.string().required(),
          city: Joi.string().required(),
          keyword: Joi.string().alphanum().required()
        },
        headers: Joi.object({
             'authorization': Joi.string().required()
        }).unknown()
      }
    },
    handler: function(request, reply) {
      //Fetch all data from mongodb User Collection
      PostModel.find({
        $and: [{
          country: request.query.country
        }, {
          city: request.query.city
        }, {
          $or: [{
            keyword_1: request.query.keyword
          }, {
            keyword_2: request.query.keyword
          }, {
            keyword_3: request.query.keyword
          }]
        }]
      }, function(error, data) {
        if (error) {
          reply(Boom.badImplementation('PostModel.find failed'));
        } else {
          if (Array.isArray(data)) {
            var mappedArray = data.map(function(mongo_data) {
              var mappedData = {};
              mappedData.country = mongo_data.country;
              mappedData.city = mongo_data.city;
              mappedData.keyword_1 = mongo_data.keyword_1;
              mappedData.keyword_2 = mongo_data.keyword_2;
              mappedData.keyword_3 = mongo_data.keyword_3;
              mappedData.id = mongo_data.id;
              mappedData.description = mongo_data.description;
              return mappedData;
            });
            reply({
              data: mappedArray
            }).code(200);
          } else {
            reply({
              data: data
            }).code(200);
          }
        }
      });
    }
  });

  server.route({
    method: 'GET',
    path: '/api/v1/post/{post_id}',
    config: {
      auth: 'jwt',
      // Include this API in swagger documentation
      tags: ['api'],
      description: 'get post with id',
      validate: {
        params: {
          post_id: Joi.objectId().required() //joi-objectid package validates that the value is an alphanumeric string of 24 characters in length
        },
        headers: Joi.object({
             'authorization': Joi.string().required()
        }).unknown()
      }
    },
    handler: function(request, reply) {
      //Fetch all data from mongodb User Collection
      PostModel.findOne({
        _id: request.params.post_id
      }, function(error, data) {
        if (error) {
          reply(Boom.badImplementation('PostModel.findOne for post id failed'));
        } else {
            if (data === null) {
              return reply({
                data: []
              }).code(200);
            }
            //sanitize: don't send all the data in the response
            var mappedData = {};
            mappedData.country = data.country;
            mappedData.city = data.city;
            mappedData.keyword_1 = data.keyword_1;
            mappedData.keyword_2 = data.keyword_2;
            mappedData.keyword_3 = data.keyword_3;
            mappedData.id = data.id;
            mappedData.description = data.description;
            return reply({
              data: mappedData
            }).code(200);
          }
        });
      }
    });

    server.route({
      method: 'DELETE',
      path: '/api/v1/post/{post_id}',
      config: {
        auth: 'jwt',
        // Include this API in swagger documentation
        tags: ['api'],
        description: 'delete post with id',
        validate: {
          params: {
            post_id: Joi.objectId().required() //joi-objectid package validates that the value is an alphanumeric string of 24 characters in length
          },
          headers: Joi.object({
               'authorization': Joi.string().required()
          }).unknown()
        }
      },
      handler: function(request, reply) {

        var userId = 0;
        try {
          var decoded = JWT.verify(request.headers.authorization, process.env.JWT_SECRET);
          userId = decoded.user_id;
        } catch(err) {
          return reply(Boom.badData('auth token is invalid'));
        }

        PostModel.findOneAndRemove({ _id: request.params.post_id, user_id: userId },
          function(err) {
            if (err) {
              return reply(Boom.badImplementation('add comment failed'));
            }
            return reply().code(200);
          });
        }
      });

    server.route({
      method: 'POST',
      path: '/api/v1/post/{post_id}/comment',
      config: {
        auth: 'jwt',
        // Include this API in swagger documentation
        tags: ['api'],
        description: 'create a comment for a post',
        validate: {
          params: {
            post_id: Joi.objectId().required() //joi-objectid package validates that the value is an alphanumeric string of 24 characters in length
          },
          payload: {
            text: Joi.string().required() //todo: need to add limits to all client input strings
          },
          headers: Joi.object({
               'authorization': Joi.string().required()
          }).unknown()
        }
      },
      handler: function(request, reply) {
        // Create mongodb user object to save it into database
        var payloadWithUserId = request.payload;
        try {
          var decoded = JWT.verify(request.headers.authorization, process.env.JWT_SECRET);
          payloadWithUserId.user_id = decoded.user_id;
        } catch(err) {
          return reply(Boom.badData('auth token is invalid'));
        }

        //really nice with mongoose query
        PostModel.where('_id').equals(request.params.post_id)
          .update({$push:{comments:payloadWithUserId}}).exec(function (err, raw) {
            if (err !== null) {
              return reply(Boom.badImplementation('add comment failed'));
            }
            return reply().code(201);
          });
      }
    });

    server.route({
      method: 'GET',
      path: '/api/v1/post/{post_id}/comment',
      config: {
        auth: 'jwt',
        // Include this API in swagger documentation
        tags: ['api'],
        description: 'get all comments for a post',
        validate: {
          params: {
            post_id: Joi.objectId().required() //joi-objectid package validates that the value is an alphanumeric string of 24 characters in length
          },
          headers: Joi.object({
               'authorization': Joi.string().required()
          }).unknown()
        }
      },
      handler: function(request, reply) {
        PostModel.findOne({
          _id: request.params.post_id
          }, function(error, data) {
          if (error) {
            reply(Boom.badImplementation('PostModel.find failed comments'));
          } else {
            if (Array.isArray(data.comments)) {
              var mappedArray = data.comments.map(function(mongo_data) {
                var mappedData = {};
                mappedData.text = mongo_data.text;
                return mappedData;
              });
              return reply({
                data: mappedArray
              }).code(200);
            } else {
              return reply({
                data: data.comments
              }).code(200);
            }
          }
        })
      }
    });

  server.route({
    method: 'GET',
    path: '/api/v1/keywords',
    config: {
      auth: 'jwt',
      // Include this API in swagger documentation
      tags: ['api'],
      description: 'get keywords for country&city',
      validate: {
        query: {
          country: Joi.string().required(),
          city: Joi.string().required(),
        },
        headers: Joi.object({
             'authorization': Joi.string().required()
        }).unknown()
      }
    },
    handler: function(request, reply) {
      //Fetch all data from mongodb User Collection
      PostModel.find({
        country: request.query.country,
        city: request.query.city
      }, function(error, data) {
        if (error) {
          reply(Boom.badImplementation('PostModel.find failed keywords'));
        } else {
          if (Array.isArray(data)) {
            var keywords = []; //will collect all keywords and output list without duplicates
            for (var record of data) {
              var set = record.keyword_1 in keywords;
              if (!set) {
                keywords.push(record.keyword_1);
                continue;
              }
              set = record.keyword_2 in keywords;
              if (!set) {
                keywords.push(record.keyword_2);
                continue;
              }
              set = record.keyword_3 in keywords;
              if (!set) {
                keywords.push(record.keyword_3);
                continue;
              }
            }
            reply({
              data: keywords
            }).code(200);
          } else {
            reply({
              data: []
            }).code(200);
          }
        }
      });
    }
  });

  // Start the server
  server.start((err) => {

    if (err) {
      throw err;
    }

    console.log('Server running at:', server.info.uri);
  });
});
