import {Button, View} from "react-native";
import {checkSSL} from "@/modules/ssl-check/sslCheck";

export default function Index() {
    return <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center'}}>
        <Button title={'SSL check'} onPress={async ()=> {
            try {
                const result = await checkSSL('https://google.com', 'sha256/srgsergesrg')
                console.log('result', result)
            } catch (error) {
                console.log('ERROR:', error)
            }
        }} />
    </View>
}