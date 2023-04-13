const { createApp } = Vue;

const app = createApp({
    data() {
        let url = new URL(window.location);
        console.debug("page URL: ", url);
        let redirect_url = new URL(url.searchParams.get('redirect_uri'));
        console.debug("redirect URL: ", redirect_url);
        return {
            redirect_url: redirect_url,
            redirect_domain: redirect_url.hostname,
            query_params: url.searchParams,
            client_id: url.searchParams.get('client_id'),
            email: '',
            password: '',
            loading: false,
        };
    },
    mounted() {
        console.debug("Vue app mounted");
    },
    computed: {

    },
    methods: {
        login(event) {
            console.debug('method login', event);
            this.loading = true;
            let self = this;
            axios.post('/auth/oauth2/login?'+this.query_params, {
                'email': this.email,
                'password': this.password
            }).then(response => {
                console.debug(response);
                self.redirect_url.searchParams.set('code', response.data.code)
                window.location.href = self.redirect_url.href;
            }).catch(e => {
                console.error(e);
            }).finally(() => {
                self.loading = false;
            });
        }
    }
});

window.addEventListener('DOMContentLoaded', (event) => {
    console.debug('DOM fully loaded and parsed', event);
    app.mount('#app');
});
