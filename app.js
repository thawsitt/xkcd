/*
 * Xkcd Comics Bot
 * ---------------
 * Read xkcd comics on Facebook Messenger.
 *
 * Author: Thawsitt Naing (thawsitt@cs.stanford.edu) See Credits in CREDITS file at repo source.
 *
 * Credit: Starter code from Facebook Developers website found here:
 * https://github.com/fbsamples/messenger-platform-samples/tree/tutorial-starters/quick-start
 *
 * Copyright (c) 2016-present, Facebook, Inc. All rights reserved.
 *
 * You are hereby granted a non-exclusive, worldwide, royalty-free license to use,
 * copy, modify, and distribute this software in source code or binary form for use
 * in connection with the web services and APIs provided by Facebook.
 * 
 * As with any software that integrates with the Facebook platform, your use of
 * this software is subject to the Facebook Developer Principles and Policies
 * [http://developers.facebook.com/policy/]. This copyright notice shall be
 * included in all copies or substantial portions of the software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request');

var Promise = require('promise');
var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

/* Constant values for payload actions */
const kGetStartedButton = 'GET_STARTED';
const kAbout = 'ABOUT';
const kLatest = 'LATEST';
const kRandom = 'RANDOM';
const kReadMore = 'READ_MORE';

/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will 
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some 
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've 
 * created. If we receive a message with an attachment (image, video, audio), 
 * then we'll simply confirm that we've received the attachment.
 * 
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s", 
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);
    handlePayload(senderID, quickReplyPayload);
    return;
  }

  if (messageText) {
    showOptions(senderID);
  } 

  else if (messageAttachments) {
    _log(messageAttachments[0].payload.sticker_id);
    if (messageAttachments[0].payload.sticker_id == 369239263222822) { // If user sent a thumbs-up
        sendTextMessage(senderID, "=)") // replies with a smile
        .then(showNextButton.bind(null, senderID));
    } else {
        sendTextMessage(senderID, "Message with attachment received");       
    }
  }
}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s", 
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll check the payload and handle accordingly
  handlePayload(senderID, payload);
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 * 
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 * 
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  return callSendAPI(messageData);
}


/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
    return new Promise(function (resolve, reject) { // ***
        request({
            uri: 'https://graph.facebook.com/v2.6/me/messages',
            qs: { access_token: PAGE_ACCESS_TOKEN },
            method: 'POST',
            json: messageData
        }, function (error, response, body) {
            if (!error && response.statusCode == 200) {
                var recipientId = body.recipient_id;
                var messageId = body.message_id;
                if (messageId) {
                    console.log("Successfully sent message with id %s to recipient %s", 
                                messageId, recipientId);
                } else {
                    console.log("Successfully called Send API for recipient %s", 
                                recipientId);
                }
                resolve(body); // ***
            } else {
                console.error("Failed calling Send API", response.statusCode,
                              response.statusMessage, body.error);
                reject(body.error); // ***
            }
        });
    });
}

/* --- The following fuctions are for XKCD comics bot. Written by Thawsitt. --- */

/*
 ===========================================================
                         USER INTERFACE
 ===========================================================
 */

/**
 * Function: showGreetingText
 * --------------------------
 * Sets the greeting text which is shown to new users. 
 *
 * Note: If you want to test this, delete the messages
 * and go to the app page again (https://m.me/xkcd.chat).
 */
function addGreetingText() {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/thread_settings',
    qs: { 
      access_token: PAGE_ACCESS_TOKEN,
    },
    method: 'POST',
    json: {
      setting_type: "greeting",
      greeting: {
        // Greeting text shown to the user
        text: "Hi {{user_first_name}}. Ready to read xkcd comics?"
      }
    }
  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      _log("Success: Greeting text set.");
     } else {
      _log('Setting greeting text FAILED.');
      console.error("Error in setting greeting text: ", response.statusCode, response.statusMessage, body.error);
    }
  });
}

/**
 * Function: removeGreetingText
 * ----------------------------
 * Removes the greeting text which is shown to new users.
 *
 * Note: This functions is currently not called anywhere. 
 * It is only here for completeness.
 */
function removeGreetingText() {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/thread_settings',
    qs: { 
      access_token: PAGE_ACCESS_TOKEN,
    },
    method: 'DELETE',
    json: {
      setting_type: "greeting"
    }
  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      _log("Greeting text removed.")
     } else {
      _log('Setting greeting text FAILED.');
      console.error("Error in removing greeting text: ", response.statusCode, response.statusMessage, body.error);
    }
  });
}

/**
 * Function: showGetStartedButton
 * ------------------------------
 * Initializes "Get Started" button which is shown to new users. 
 *
 * Note: If you want to test this, delete the messages 
 * and go to the app page again (https://m.me/quas.chat).
 */
function addGetStartedButton() {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/thread_settings',
    qs: { 
      access_token: PAGE_ACCESS_TOKEN,
    },
    method: 'POST',
    json: {
      setting_type: "call_to_actions",
      thread_state: "new_thread",
      call_to_actions: [
        {
          "payload": kGetStartedButton
        }
      ]
    }
  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      _log("Success: GET STARTED BUTTON set.");
     } else {
      _log('Cannot set GET STARTED BUTTON');
      console.error("Error in setting Get Started button: ", response.statusCode, response.statusMessage, body.error);
    }
  });
}

/**
 * Function: removeGetStartedButton
 * --------------------------------
 * Removes the "Get Started" button which is shown to new users.
 *
 * Note: This functions is currently not called anywhere. 
 * It is only here for completeness.
 */
function removeGetStartedButton() {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/thread_settings',
    qs: { 
      access_token: PAGE_ACCESS_TOKEN,
    },
    method: 'DELETE',
    json: {
      setting_type: "call_to_actions",
      thread_state: "new_thread"
    }
  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      _log("Success: GET STARTED BUTTON removed.");
     } else {
      _log('Cannot remove GET STARTED BUTTON');
      console.error("Error in removing Get Started button: ", response.statusCode, response.statusMessage, body.error);
    }
  });
}


/**
 * Function: addPersistentMenu
 * --------------------------------
 * Adds a persistent menu (looks like a "menu" button on the left side) 
 * which provides different options for users to choose from.
 */
function addPersistentMenu(){
  request({
    url: 'https://graph.facebook.com/v2.6/me/thread_settings',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json:{
      setting_type : "call_to_actions",
      thread_state : "existing_thread",
      call_to_actions:[
      {
        type:"postback",
        title:"About",
        payload: kAbout
      },
      {
        type:"postback",
        title:"Latest comic",
        payload: kLatest
      },
      {
        type:"postback",
        title:"Random comic",
        payload: kRandom
      },
      {
        type:"web_url",
        title:"Visit xkcd",
        url:"http://xkcd.com/"
      }
      ]
    }
  }, function(error, response, body) {
    //console.log(response)
    if (error) {
      console.log('Error adding persistent menu: ', error)
    } else if (response.body.error) {
      console.log('Error: ', response.body.error)
    } else {
      _log("Added Persistent Menu.");
    }
  });
}

function removePersistentMenu(){
  request({
    url: 'https://graph.facebook.com/v2.6/me/thread_settings',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'DELETE',
    json:{
      setting_type : "call_to_actions",
      thread_state : "existing_thread",
    }
  }, function(error, response, body) {
  //console.log(response)
    if (error) {
      console.log('Error sending messages: ', error)
    } else if (response.body.error) {
      console.log('Error: ', response.body.error)
    }
  });
}


/*
 ===========================================================
                     BOT FUNCTIONALITIES
 ===========================================================
 */

/**
 * Function: handlePayload
 * -----------------------
 * This function is called when a user sent a message with payload. 
 * (e.g: user pressed a button.) 
 * 
 * This function calls appropriate fuction based on the payload.
 */
function handlePayload(senderID, payload) {
  if (payload == kGetStartedButton) {
    showIntro(senderID);
  }

  else if (payload == kLatest) {
    sendLatestXkcd(senderID);
  }

  else if (payload == kRandom) {
    sendRandomXkcd(senderID);
  }

  else if (payload = kAbout) {
    showAbout(senderID);
  }

  else {
    sendTextMessage(senderID, "Payload received.");
  }
}

function showAbout(recipientId) {
    sendTextMessage(recipientId, "Xkcd Comics Bot is an open-source project maintained by Thawsitt Naing.")
    .then(sendTextMessage.bind(null, recipientId, "To contribute or give feedback, please visit https://github.com/thawsitt/xkcd-comics-bot"))
    .then(sendTextMessage.bind(null, recipientId, "This bot is not affiliated with xkcd.com. Thanks for visiting us."))
    .catch((error) => _log("Error showing About section. Details: " + error));
}

function showOptions(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What do you want to read?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"latest xkcd",
          "payload": kLatest
        },
        {
          "content_type":"text",
          "title":"random xkcd",
          "payload": kRandom
        }
      ]
    }
  };

  callSendAPI(messageData);   
}

function showNextButton(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "Do you want to read another one?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Show me more!",
          "payload": kRandom
        }
      ]
    }
  };

  callSendAPI(messageData);
}


function sendLatestXkcd(senderID) {
  getXkcdComic('http://xkcd.com/info.0.json')
  .then((body) => {
    let xkcd = JSON.parse(body);
    let messageData = {
      recipient: {
        id: senderID
      },
      message: {
        attachment: {
          type: "image",
          payload: {
            url: getHighResImg(xkcd.img, xkcd.num)
          }
        }
      }
    };
    sendTextMessage(senderID, "Here is the latest comic (" +  "#" + xkcd.num + ") from xkcd.")
    .then(sendTextMessage.bind(null, senderID, '"' + xkcd.safe_title + '"'))
    .then(callSendAPI.bind(null, messageData))
    .then(showNextButton.bind(null, senderID));
  })
  .catch((error) => {
    _log("Error getting latest Xkcd comic." + error);
    sendTextMessage(senderID, "Sorry, I am having trouble getting content from xkcd."); //TODO: Send a button go to xkcd website
  });
}

function sendRandomXkcd(senderID) {
  let latestID = 1800; // latest id as of Feb 2017

  getXkcdComic('http://xkcd.com/info.0.json')
  .then((body) => {
    latestID = JSON.parse(body).num;
    let randomXkcdID = Math.floor(Math.random() * latestID) + 1; // random number between 1 and latest ID, inclusive.
    if (randomXkcdID < 1700) {
      randomXkcdID += 100; // prefer newer comics
    }
    _log("Random xkcd comic id: " + randomXkcdID);
    let url = 'http://xkcd.com/' + randomXkcdID + '/info.0.json';

    getXkcdComic(url)
    .then((body) => {
      let xkcd = JSON.parse(body);
      let messageData = {
        recipient: {
          id: senderID
        },
        message: {
          attachment: {
            type: "image",
            payload: {
              url: getHighResImg(xkcd.img, xkcd.num)
            }
          }
        }
      }
      sendTextMessage(senderID, "Sure! Here is a random comic (" +  "#" + xkcd.num + ") from xkcd.")
      .then(sendTextMessage.bind(null, senderID, '"' + xkcd.safe_title + '"'))
      .then(callSendAPI.bind(null, messageData))
      .then(showNextButton.bind(null, senderID));
    });
  })
  .catch((error) => _log("ERROR in getting random comic. Details: " + error));
}

/**
 * Function: getHighResImg
 * -----------------------
 * Xkcd API only returns the url of low-res image.
 * However, their website hosts high-res images.
 * 
 * This function replaces the url of low-res img with
 * the high-res one.
 *
 * Note: Only comics with id >= 1084 have high-res images.
 */
function getHighResImg(url, id) {
  if (id >= 1084) {
    return url.replace('.png', '_2x.png');
  } else {
    return url;
  }
}

function getXkcdComic(xkcdUrl) {
  return new Promise(function (resolve, reject) { // ***
    request({
      uri: xkcdUrl,
      method: 'GET',
  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      _log("Get Xkcd SUCCESS.");
      console.log(body); // left for debugging
      resolve(body); // *** user info JSON
      } else {
        _log("Get Xkcd FAILED.");
        console.error("Failed calling Xkcd API", response.statusCode,
          response.statusMessage, body.error);
        reject(body.error); // ***
      }
    });
  });
}

/**
 * Function: showIntro
 * -------------------
 * Explains the user about xkcd comics bot.
 */
 
function showIntro(senderID) {
  var intro = "Welcome to xkcd comics bot!";
  getUserInfo(senderID)
  .then((body) => {
    var user_first_name = JSON.parse(body).first_name;
    if (user_first_name) {
      sendTextMessage(senderID, "Hi " + user_first_name + ". " + intro)
      .then(sendTextMessage.bind(null, senderID, "Here, you will have access to all your favorite xkcd comics." ))
      .then(sendTextMessage.bind(null, senderID, "Let's get started. Hope you enjoy it!!"))
      .then(showOptions.bind(null, senderID))
      .catch((error) => _log('showIntro function failed.'));
    } else {
      sendTextMessage(senderID, intro);
    }
  })
  .catch((err) => {
    sendTextMessage(senderID, intro);
    console.error("Cannot get user information: ", err);
  });
} 


/**
 * Function: GET USER INFO
 * -----------------------
 * Promise compatible function which returns a JSON representation
 * of user information (first name, last name, gender, locale, timezone) on success.
 */
function getUserInfo(senderID) {
  return new Promise(function (resolve, reject) { // ***
    request({
      uri: 'https://graph.facebook.com/v2.6/' + senderID,
      qs: { 
        access_token: PAGE_ACCESS_TOKEN,
    },
    method: 'GET',
  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      _log("Get User Info SUCCESS.");
      // console.log(body); // left for debugging
      resolve(body); // *** user info JSON
      } else {
        _log("Get User Info FAILED.");
        console.error("Failed calling Send API", response.statusCode,
          response.statusMessage, body.error);
        reject(body.error); // ***
      }
    });
  });
}


/**
 * (helper) Function: _log
 * ------------------------
 * Makes an important message (log) easier to read
 * in the console.
 */
function _log(msg) {
  console.log('=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=');
  console.log(msg);
  console.log('=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=');
}


// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
  addGreetingText();
  addGetStartedButton();
  addPersistentMenu();
});

module.exports = app;

