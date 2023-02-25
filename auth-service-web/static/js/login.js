
/* global Vue, $, toastr */

var app = null;

$(document).ready(function() {
   app = new Vue({
       el: "#app",
       data: {
           email: null,
           pwd: null,
           errors: []
       },
       mounted: function() {
           window.addEventListener('keydown', function(event) {
               if (event.code === "Enter") {
                   app.login();
               }
           });
       },
       methods: {
           login: function() {
                if(this.checkLogin()) {
                    doLogin();
                } else {

                }
           },
           checkLogin: function() {
               this.errors = [];

               if(!this.email) {
                   this.errors.push("Email required.");
               } else if(!this.validEmail(this.email)) {
                   this.errors.push("Valid email required.");
               }
               if(!this.pwd) {
                   this.errors.push("Password required.");
               }

               return this.errors.length === 0;
           },
           validEmail: function(email) {
               const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
               return re.test(email);
           }
       }
   });
});

function doLogin() {
    $.ajax({
        url: '/auth/login',
        type: 'post',
        dataType: 'json',
        headers: {
            'Content-Type': 'application/json'
        },
        data: JSON.stringify({
            'email':  app.email,
            'password': app.pwd
        })
    }).done(function(data) {
        sessionStorage.setItem('token', data.token);
        let urlSearchParams = new URLSearchParams(window.location.search);
        window.location.href = urlSearchParams.get('redirect');
    }).fail(function() {
        toastr.error('The access data are incorrect!');
    });
}
