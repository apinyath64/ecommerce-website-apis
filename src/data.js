async function getData() {
    const url = "https://raw.githubusercontent.com/kongvut/thai-province-data/master/api_province_with_amphure_tambon.json"
    
    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Response status: ${response.status}`);
        }

        const result = await response.json()
        // console.dir(result, { depth: null })

        for (const province of result) {
            console.log(`Province: ${province.name_th} (${province.name_en})`);

        }

        
    } catch (error) {
        console.log(error.message);
        
    }

}

getData()