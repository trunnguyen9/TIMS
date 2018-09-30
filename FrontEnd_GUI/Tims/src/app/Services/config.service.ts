import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders} from '@angular/common/http';
import { Config } from '../Components/config/config.component';

const httpOptions = {
  headers: new HttpHeaders({ 'Content-Type': 'application/json' })
};

@Injectable({
  providedIn: 'root'
})
export class ConfigService {
  configUrl = 'http://127.0.0.1:5000/';

  constructor(private http: HttpClient) {  }

  getConfig() {
    return this.http.get<Config>(this.configUrl + 'getConfig');
  }

  updateConfig(config: Config) {
    return this.http.put(this.configUrl + 'updateConfig', config , httpOptions);
  }
}
