import { Injectable } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {DataByProvider} from '../Components/statistic/statistic.component';


@Injectable({
  providedIn: 'root'
})
export class StatisticService {
  configUrl = 'http://127.0.0.1:5000/';
  constructor(private http: HttpClient) { }

  getStatisticByProvider() {
    return this.http.get<DataByProvider[]>(this.configUrl + 'statisticByProvider');
  }
}
