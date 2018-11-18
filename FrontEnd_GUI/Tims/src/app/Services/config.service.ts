import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders} from '@angular/common/http';
import { Config } from '../Components/config/config.component';
import { environment } from '../../environments/environment.prod';

const httpOptions = {
  headers: new HttpHeaders({ 'Content-Type': 'application/json' })
};

@Injectable({
  providedIn: 'root'
})
export class ConfigService {
  constructor(private http: HttpClient) {  }

  getConfig() {
    return this.http.get<Config>(environment.apiEndpoint + '/getConfig');
  }

  updateConfig(config: Config) {
    return this.http.put(environment.apiEndpoint + '/updateConfig', config , httpOptions);
  }
}
