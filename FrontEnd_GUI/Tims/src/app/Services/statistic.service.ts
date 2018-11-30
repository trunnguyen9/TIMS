import { Injectable } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {DataByProvider} from '../Components/statistic/statistic.component';
import { environment } from '../../environments/environment.prod';

@Injectable({
  providedIn: 'root'
})
export class StatisticService {

  constructor(private http: HttpClient) { }

  getStatisticByProvider() {
    return this.http.get<DataByProvider[]>(environment.apiEndpoint + '/statisticByProvider');
  }
}
