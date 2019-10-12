# Auth0 ID4me Sample Client Application
This is a sample Node.js client application accompanying the blog post at https://auth0.com/blog/auth0-integration-id4me/

## 1. Clone this repository

`git clone git@github.com:auth0-blog/auth0-id4me-sample.git`

## 2. Configure environment

On your computer, switch to the folder where you checked out the project. Copy the `.env.sample` file to  `.env`:

`cp .env.sample .env` (depending on your OS, the command might differ)

Open the `.env` file in a text editor and adjust the values in it:

* `AUTH0_DOMAIN`: your Auth0 tenant domain (without `https://`)
* `AUTH0_CLIENT_ID`: the `client_id` from step 2 above
* `AUTH0_CLIENT_SECRET`: the `client_secret` from step 2 above

## 3. Build and run

When finished, build and run the app:

```
npm install
npm start
```

and open the browser on `http://localhost:3000`.

The client application is now up and running and you can test it with your ID4me user.
