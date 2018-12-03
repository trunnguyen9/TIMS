import { Injectable } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import { environment } from '../../environments/environment';
import {DataByProvider} from '../Components/provider-chart/provider-chart.component';

@Injectable({
  providedIn: 'root'
})
export class StatisticService {

  constructor(private http: HttpClient) { }

  getStatisticByProvider() {
    return this.http.get<DataByProvider[]>(environment.apiEndpoint + '/statisticByProvider');
  }

  getStatisticByThreat() {
    return this.http.get(environment.apiEndpoint + '/statisticByThreat');
  }

  getStatisticByTags() {
    return this.http.get(environment.apiEndpoint + '/statisticByTags');
  }
}
