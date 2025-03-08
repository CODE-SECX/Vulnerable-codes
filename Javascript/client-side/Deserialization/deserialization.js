app.post('/api/data', (req, res) => {
    // Vulnerable: Directly parsing JSON from request body
    const userData = JSON.parse(req.body.data);
    
    // Use userData...
    res.send('Data processed');
  });

  function processUserConfig(request) {
    // Vulnerable: Using eval on user input
    const config = eval('(' + request.body.config + ')');
    return config;
  }

  const serialize = require('node-serialize');
const express = require('express');
const app = express();

app.post('/deserialize', (req, res) => {
  // Vulnerable: Deserializing untrusted input
  const obj = serialize.unserialize(req.body.data);
  
  // Use obj...
  res.send('Object processed');
});

class DataHandler {
    static process(input) {
      // Vulnerable: Custom deserialize method with untrusted input
      return DataHandler.deserialize(input.userData);
    }
    
    static deserialize(data) {
      return JSON.parse(data);
    }
  }

  app.get('/execute', (req, res) => {
    // Vulnerable: Creating a function from user input
    const userFunc = new Function(req.query.code);
    
    const result = userFunc();
    res.send(result);
  });

  function mergeConfigs(userConfig) {
    const config = {};
    
    // Vulnerable: Possible prototype pollution
    Object.setPrototypeOf(config, JSON.parse(userConfig));
    
    return config;
  }

  const vm = require('vm');

app.post('/sandbox', (req, res) => {
  // Vulnerable: Executing code in VM with user input
  const sandbox = { result: null };
  vm.runInNewContext(req.body.code, sandbox);
  
  res.json({ result: sandbox.result });
});

function validateInput(req) {
    // Vulnerable: Creating RegExp from user input
    const userPattern = new RegExp(req.body.pattern);
    
    return userPattern.test(req.body.text);
  }

  const yaml = require('js-yaml');

app.post('/config', (req, res) => {
  try {
    // Vulnerable: Loading YAML from user input
    const config = yaml.load(req.body.config);
    
    // Use config...
    res.send('Config processed');
  } catch (e) {
    res.status(400).send('Invalid YAML');
  }
});

const libxmljs = require('libxmljs');

function processXML(userInput) {
  // Vulnerable: Parsing XML with external entities enabled
  const xmlDoc = libxmljs.parseXml(userInput.data, {
    noent: true
  });
  
  return xmlDoc;
}

app.post('/data', (req, res) => {
    // Vulnerable: JSON parse with custom reviver function
    const userData = JSON.parse(req.body.data, function(key, value) {
      if (key === 'exec') {
        return eval(value);
      }
      return value;
    });
    
    res.json(userData);
  });

  function processQueryParams() {
    // Vulnerable: Parsing URL parameters without validation
    const params = JSON.parse(decodeURIComponent(location.search.substring(1)));
    
    return params;
  }

  const BSON = require('bson');

app.post('/mongo', (req, res) => {
  // Vulnerable: Deserializing BSON from user input
  const doc = BSON.deserialize(req.body.bson);
  
  // Use doc...
  res.send('Document processed');
});

function UserProfile({ userData }) {
    // Vulnerable: Rendering HTML from user input
    return (
      <div 
        dangerouslySetInnerHTML={{ __html: userData.bio }}
      />
    );
  }

  function processQueryParams() {
    // Vulnerable: Parsing URL parameters without validation
    const params = JSON.parse(decodeURIComponent(location.search.substring(1)));
    
    return params;
  }

  function loadUserSettings() {
    // Vulnerable: Parsing potentially manipulated localStorage data
    const settings = JSON.parse(localStorage.getItem('userSettings'));
    
    applySettings(settings);
  }

  const { remote } = require('electron');

function executeRemoteCode(input) {
  // Vulnerable: Using Electron's remote module
  return remote.app.getPath(input.path);
}

window.addEventListener('message', function(event) {
    // Vulnerable: Processing messages from other windows
    if (event.origin === 'https://trusted-source.com') {
      const data = JSON.parse(event.data);
      processData(data);
    }
  });

  function updateConfig(req) {
    const config = { 
      version: '1.0',
      debug: false
    };
    
    // Vulnerable: Merging objects with user input
    Object.assign(config, JSON.parse(req.body.config));
    
    return config;
  }

  const _ = require('lodash');

app.post('/template', (req, res) => {
  // Vulnerable: Compiling templates from user input
  const compiled = _.template(req.body.template);
  
  const result = compiled({ data: req.body.data });
  res.send(result);
});