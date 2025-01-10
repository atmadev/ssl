# Welcome to your Expo app 👋

This is an [Expo](https://expo.dev) project created with [`create-expo-app`](https://www.npmjs.com/package/create-expo-app).

## Get started

1. Install dependencies

   ```bash
   npm install
   ```

2. Start the app

   ```bash
    npm run ios
    npm run android
   ```

In the output, you'll find options to open the app in a

- [Android emulator](https://docs.expo.dev/workflow/android-studio-emulator/)
- [iOS simulator](https://docs.expo.dev/workflow/ios-simulator/)

## Task

Native code is located in `modules/ssl-check/ios|android` directories respectfully, documentation on how Expo Modules work is [here](https://docs.expo.dev/modules/module-api/). The task is to implement `checkSSL` function so it success with correct `url`/`publicKey`(which is SHA256 hash of SSL certificate public key) and fails when `publicKey` doesn't match to certificate of domain of `url`.

## Learn more

To learn more about developing your project with Expo, look at the following resources:

- [Expo documentation](https://docs.expo.dev/): Learn fundamentals, or go into advanced topics with our [guides](https://docs.expo.dev/guides).
