import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { AppComponent } from './app.component';
import { LoginComponent } from './Components/login/login.component';
import { RegisterComponent } from './Components/register/register.component';
import { AppRoutingModule } from './app-routing.module';
import { ConfigComponent } from './Components/config/config.component';
import { HomeComponent } from './Components/home/home.component';
import { NavbarComponent } from './Components/navbar/navbar.component';
import { StatisticComponent } from './Components/statistic/statistic.component';
import {HTTP_INTERCEPTORS, HttpClientModule} from '@angular/common/http';
import { HttpModule } from '@angular/http';
import { ChartModule } from 'angular-highcharts';
import { FooterComponent } from './Components/footer/footer.component';
import { AboutusComponent } from './Components/aboutus/aboutus.component';
import { DownloadComponent } from './Components/download/download.component';
import { PasswordChangeComponent } from './Components/password-change/password-change.component';
import {JwtInterceptor} from './Helpers/jwt.interceptor';
import { TabsComponent } from './Components/tabs/tabs.component';
import { TabComponent } from './Components/tab/tab.component';

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    RegisterComponent,
    ConfigComponent,
    HomeComponent,
    NavbarComponent,
    StatisticComponent,
    FooterComponent,
    AboutusComponent,
    DownloadComponent,
    PasswordChangeComponent,
    TabsComponent,
    TabComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    ReactiveFormsModule,
    HttpClientModule,
    ChartModule,
    HttpModule
  ],
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: JwtInterceptor,
      multi: true
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
