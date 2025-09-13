// JavaScript vulnerability test file
function processInput(userInput) {
    // XSS vulnerability
    document.getElementById('output').innerHTML = userInput;
    
    // Code injection vulnerability  
    eval('var result = ' + userInput);
    
    // Weak randomness
    var sessionId = Math.random().toString();
    
    return result;
}

// setTimeout with string parameter - code injection risk
setTimeout("alert('test')", 1000);