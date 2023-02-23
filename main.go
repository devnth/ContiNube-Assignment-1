package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
)

type Data struct {
	Vulnerabilities []struct {
		Cve struct {
			ID               string `json:"id"`
			SourceIdentifier string `json:"sourceIdentifier"`
			Published        string `json:"published"`
			LastModified     string `json:"lastModified"`
			VulnStatus       string `json:"vulnStatus"`

			Metrics struct {
				CvssMetricV2 []struct {
					CvssData struct {
						VectorString string `json:"vectorString"`

						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

var wg sync.WaitGroup

func main() {

	bodyBytes := []byte{}

	var input string = "CVE-1999-0082,CVE-1999-0095"

	ch := make(chan map[string]string)
	// chErr := make(chan error)

	// fmt.Println("Enter the cve Ids(Should be separated by coma)")
	// fmt.Scan(&input)

	fmt.Println("id's: ", input)

	ids := strings.Split(input, ",")

	for i := 0; i < len(ids); i++ {

		wg.Add(1)

		id := ids[i]

		api := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", id)

		go func(api string) {

			client := &http.Client{}

			req, err := http.NewRequest("GET", api, nil)
			if err != nil {
				fmt.Print(err.Error())
			}
			req.Header.Add("Accept", "application/json")
			req.Header.Add("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				fmt.Print(err.Error())
			}

			defer resp.Body.Close()
			bodyBytes, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Print(err.Error())
			}
			fmt.Println("Inside go routine")
			var responseObject Data
			json.Unmarshal(bodyBytes, &responseObject)

			result := make(map[string]string)

			for _, v := range responseObject.Vulnerabilities {

				result["ID"] = v.Cve.ID
				result["Published"] = v.Cve.Published
				result["LastModified"] = v.Cve.LastModified
				result["VulnStatus"] = v.Cve.VulnStatus

				for _, v1 := range v.Cve.Metrics.CvssMetricV2 {

					result["VectorString"] = v1.CvssData.VectorString
					result["BaseScore"] = fmt.Sprint(v1.CvssData.BaseScore)
					result["BaseSeverity"] = v1.BaseSeverity

				}

			}
			// fmt.Println(result)

			ch <- result
			wg.Done()
		}(api)

	}

	go func() {
		defer close(ch)
		wg.Wait()
	}()

	for resultt := range ch {
		fmt.Println("data :", resultt)
	}

}
